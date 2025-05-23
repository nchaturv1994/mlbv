"""
Streaming functions
"""

import logging

from datetime import datetime
from datetime import timezone
from dateutil import parser

import mlbv.mlbam.common.config as config
import mlbv.mlbam.common.request as request
import mlbv.mlbam.common.stream as stream
import mlbv.mlbam.common.util as util
import mlbv.mlbam.mlbapidata as mlbapidata


LOG = logging.getLogger(__name__)


def select_feed_for_team(game_rec, team_code, feedtype=None):
    found = False
    if game_rec["away"]["abbrev"] == team_code:
        found = True
        if feedtype is None and "away" in game_rec["feed"]:
            feedtype = "away"  # assume user wants their team's feed
    elif game_rec["home"]["abbrev"] == team_code:
        found = True
        if feedtype is None and "home" in game_rec["feed"]:
            feedtype = "home"  # assume user wants their team's feed
    if found:
        if feedtype is None:
            LOG.info(
                "Default (home/away) feed not found: choosing first available feed"
            )
            if game_rec["feed"]:
                feedtype = list(game_rec["feed"].keys())[0]
                LOG.info("Chose '%s' feed (override with --feed option)", feedtype)
        if feedtype not in game_rec["feed"]:
            LOG.error("Feed is not available: %s", feedtype)
            return None, None, None
        if "contentId" in game_rec["feed"][feedtype]:
            content_id = game_rec["feed"][feedtype]["contentId"]
        else:
            content_id = None
        return (
            game_rec["feed"][feedtype]["mediaPlaybackId"],
            game_rec["feed"][feedtype]["mediaState"],
            content_id,
        )
    return None, None, None


def select_feed_for_team_new(game_feeds, team_code, feedtype=None):
    found = None
    wanted_team_id = mlbapidata.get_team_id(team_code)

    video_feeds = [x for x in game_feeds if x['mediaState']['mediaType'] == 'VIDEO']

    if not video_feeds:
        LOG.info("No video feeds returned")
        return None, None, None

    available_feeds = []

    for game_feed in video_feeds:
        # Ignore non-video
        if not game_feed['mediaState']['mediaType'] == 'VIDEO':
            continue

        # Ignore feeds which are off
        if game_feed['mediaState']['state'] == 'OFF':
            continue
        available_feeds.append(game_feed)

    if not available_feeds:
        LOG.info("No video feeds available")
        return None, None, None, None

    for game_feed in available_feeds:
        # Ignore non-video
        if not game_feed['mediaState']['mediaType'] == 'VIDEO':
            continue

        # Ignore feeds which are off
        if game_feed['mediaState']['state'] == 'OFF':
            continue

        if feedtype:
            if feedtype.upper() == game_feed['feedType']:
                found = game_feed
                break
        else:
            if (
                game_feed['feedType'] == 'AWAY' and
                dict(name='AwayTeamId', value=str(wanted_team_id)) in game_feed.get('fields', [])
            ):
                found = game_feed
                break

            if (
                game_feed['feedType'] == 'HOME' and
                dict(name='HomeTeamId', value=str(wanted_team_id)) in game_feed.get('fields', [])
            ):
                found = game_feed
                break

    if not found:
        # the prefered feed doesn't exist so pick the first available one
        found = available_feeds[0]

    return found['mediaId'], found['mediaState']['state'], found['contentId'], found['milestones']


def find_highlight_url_for_team(game_rec, feedtype):
    if feedtype not in config.HIGHLIGHT_FEEDTYPES:
        raise Exception("highlight: feedtype must be condensed or recap")
    if feedtype in game_rec["feed"] and "playback_url" in game_rec["feed"][feedtype]:
        return game_rec["feed"][feedtype]["playback_url"]
    LOG.error(
        "No playback_url found for %s vs %s, info: %s",
        game_rec["away"]["abbrev"],
        game_rec["home"]["abbrev"],
        str(game_rec["feed"]),
    )
    return None


def get_game_rec(game_data, team_to_play, game_number_str):
    """game_number_str: is an string 1 or 2 indicating game number for doubleheader"""
    game_rec = None
    for game_pk in game_data:
        if team_to_play in (
            game_data[game_pk]["away"]["abbrev"],
            game_data[game_pk]["home"]["abbrev"],
        ):
            if (
                game_data[game_pk]["doubleHeader"] != "N"
                and game_number_str != game_data[game_pk]["gameNumber"]
            ):
                # game is doubleheader but not our game_number
                continue
            game_rec = game_data[game_pk]
            break
    if game_rec is None:
        if int(game_number_str) > 1:
            util.die("No second game available for team {}".format(team_to_play))
        util.die("No game found for team {}".format(team_to_play))
    return game_rec


def play_stream(
    game_rec,
    team_to_play,
    feedtype,
    date_str,
    fetch,
    record,
    from_start,
    inning_ident,
    no_evi,
    is_multi_highlight=False,
):
#    import json
#    print(json.dumps(game_rec, default=str))

    game_pk = game_rec['game_pk']



    if game_rec["doubleHeader"] != "N":
        LOG.info("Selected game number %s of doubleheader", game_rec["gameNumber"])
    if feedtype is not None and feedtype in config.HIGHLIGHT_FEEDTYPES:
        # handle condensed/recap
        playback_url = find_highlight_url_for_team(game_rec, feedtype)
        if playback_url is None:
            util.die("No playback url for feed '{}'".format(feedtype))
        return stream.play_highlight(
            playback_url,
            stream.get_fetch_filename(
                date_str,
                game_rec["home"]["abbrev"],
                game_rec["away"]["abbrev"],
                feedtype,
                fetch,
            ),
            is_multi_highlight,
        )

    # handle full game (live or archive)
    # this is the only feature requiring an authenticated session
    import mlbv.mlbam.mlbsession as mlbsession

    mlb_session = mlbsession.MLBSession()

    game_content = mlb_session.get_game_content(game_pk)
    # print(game_content)
    media_playback_id, media_state, content_id, milestones = select_feed_for_team_new(
        game_content, team_to_play, feedtype
    )
    if media_playback_id is None:
        LOG.error("No stream URL found")
        return 0

    # Authentication is triggered within here if necessary:
    stream_url = mlb_session.lookup_stream_url(game_rec["game_pk"], media_playback_id, no_evi)
    if stream_url is None:
        LOG.info("No game stream found for %s", team_to_play)
        return 0

    # stream_url = stream_url.replace('akc', 'llc')
    offset = None
    if config.SAVE_PLAYLIST_FILE:
        mlb_session.save_playlist_to_file(stream_url)
    if inning_ident:
        offset = _calculate_inning_offset(
            inning_ident, media_state, milestones, game_rec
        )
        if offset is None:
            return 0  # already logged
    return stream.streamlink(
        stream_url,
        mlb_session,
        stream.get_fetch_filename(
            date_str,
            game_rec["home"]["abbrev"],
            game_rec["away"]["abbrev"],
            feedtype,
            fetch or record,
        ),
        record,
        from_start,
        offset,
    )

def _lookup_inning_timestamp_via_milestones(
    milestones, inning, inning_half="top", overwrite_json=True
):
    stream_start = None
    for milestone in milestones:
        if milestone["milestoneType"] == "STREAM_START":
            milestone_inning = False
            stream_start_str = str(milestone["absoluteTime"])
            stream_start = parser.parse(stream_start_str).timestamp()
        elif milestone["milestoneType"] == "BROADCAST_START":
            milestone_inning = "0"
            milestone_inning_half = "top"
            broadcast_start_str = str(milestone["absoluteTime"])
            broadcast_start = parser.parse(stream_start_str).timestamp()
        elif milestone["milestoneType"] == "INNING_START":
            milestone_inning = "1"
            milestone_inning_half = "top"
            for keyword in milestone["keywords"]:
                if str(keyword["name"]) == "inning":
                    milestone_inning = str(keyword["value"])
                elif str(keyword["name"]) == "top":
                    if str(keyword["value"]) != "true":
                        milestone_inning_half = "bottom"
        else:
            continue
            
        if milestone_inning == inning and milestone_inning_half == inning_half:
            # we found it
            inning_start_timestamp_str = milestone["absoluteTime"]
            inning_start_timestamp = parser.parse(
                inning_start_timestamp_str
            ).timestamp()
            LOG.info(
                "Found inning start: %s", inning_start_timestamp_str
            )
            LOG.debug("Milestone data: %s", str(milestone))
            return (
                stream_start,
                inning_start_timestamp,
                inning_start_timestamp_str,
                )

    LOG.warning("Could not locate '%s %s' inning", inning_half, inning)
    return stream_start, None, None

# def _lookup_inning_timestamp_via_airings(
#     game_rec, media_playback_id, inning, inning_half="top", overwrite_json=True
# ):
#     broadcast_start = None
#     url = (
#         "https://search-api-mlbtv.mlb.com/svc/search/v2/graphql/persisted/"
#         "query/core/Airings?variables={{%22partnerProgramIds%22%3A[%22{gamepk}%22]}}"
#     ).format(gamepk=game_rec["game_pk"])
#     json_data = request.request_json(url, "airings", cache_stale=request.CACHE_SHORT)
#     for airing in json_data["data"]["Airings"]:
#         # there is a separate BROADCAST_START for each broadcast, so do lookup based on passed-in media id
#         LOG.debug(
#             "airing['mediaId']: %s, media_playback_id: %s",
#             str(airing["mediaId"]),
#             media_playback_id,
#         )
#         if str(airing["mediaId"]) != media_playback_id:
#             continue
#         if "milestones" not in airing:
#             LOG.warning(
#                 "_lookup_inning_timestamp_via_airings: no milestone data for airing: %s",
#                 str(airing),
#             )
#             continue
#         for milestone in airing["milestones"]:
#             if milestone["milestoneType"] == "BROADCAST_START":
#                 for milestone_time in milestone["milestoneTime"]:
#                     if str(milestone_time["type"]) == "absolute":
#                         broadcast_start_str = str(milestone_time["startDatetime"])
#                         broadcast_start = parser.parse(broadcast_start_str).timestamp()
#             elif milestone["milestoneType"] == "INNING_START":
#                 milestone_inning = "1"
#                 milestone_inning_half = "top"
#                 for keyword in milestone["keywords"]:
#                     if str(keyword["type"]) == "inning":
#                         milestone_inning = str(keyword["value"])
#                     elif str(keyword["type"]) == "top":
#                         if str(keyword["value"]) != "true":
#                             milestone_inning_half = "bottom"
#                 if milestone_inning == inning and milestone_inning_half == inning_half:
#                     # we found it
#                     for milestone_time in milestone["milestoneTime"]:
#                         if str(milestone_time["type"]) == "absolute":
#                             inning_start_timestamp_str = milestone_time["startDatetime"]
#                             # inning_start_timestamp_str = str(play['about']['startTime'])
#                             inning_start_timestamp = parser.parse(
#                                 inning_start_timestamp_str
#                             ).timestamp()
#                             LOG.info(
#                                 "Found inning start: %s", inning_start_timestamp_str
#                             )
#                             LOG.debug("Milestone data: %s", str(milestone))
#                             return (
#                                 broadcast_start,
#                                 inning_start_timestamp,
#                                 inning_start_timestamp_str,
#                             )
#
#     LOG.warning("Could not locate '%s %s' inning", inning_half, inning)
#     return broadcast_start, None, None


def _calculate_inning_offset(inning_offset, media_state, milestones, game_rec):
    inning_half = "top"
    if inning_offset.startswith("b"):
        inning_half = "bottom"
    if len(inning_offset) > 1 and inning_offset[-2].isnumeric():
        inning = inning_offset[-2:]  # double digits, extra innings
    else:
        inning = inning_offset[-1]  # single digit inning
    (
        broadcast_start_timestamp,
        inning_start_timestamp,
        inning_timestamp_str,
    ) = _lookup_inning_timestamp_via_milestones(
        milestones, inning, inning_half
    )
    if inning_start_timestamp is None:
        LOG.error("Inning '%s' not found in airing data", inning_offset)
        return None

    stream_start_offset_secs = config.CONFIG.parser.getint(
        "stream_start_offset_secs", config.DEFAULT_STREAM_START_OFFSET_SECS
    )

    # now calculate the HH:MM:SS offset for livestream.
    # It is complicated by:
    #     - if stream is live then the offset is from the end of stream
    #     - if stream is archive then offset is from beginning of stream
    if media_state == "ON":
        #     start          offset       endofstream
        #     |        | <----------------> |
        #            inning
        LOG.info(
            "Live game: game start: %s, inning start: %s",
            game_rec["mlbdate"],
            inning_timestamp_str,
        )
        now_timestamp = datetime.now(timezone.utc).timestamp()
        offset_secs = now_timestamp - inning_start_timestamp
        # Issue #9: apply the offset if provided (assume provided if not default value):
        if stream_start_offset_secs != 0:
            LOG.info(
                "Applying stream start offset: %s seconds", stream_start_offset_secs
            )
            offset_secs += stream_start_offset_secs
        LOG.debug(
            "now_timestamp: %s, inning_start_timestamp: %s, offset=%s",
            now_timestamp,
            inning_start_timestamp,
            offset_secs,
        )
        logstr = "Calculated live game negative inning offset (from now): %s"
    else:
        #     start      inning        endofstream
        #     | <--------> |                |
        #         offset
        LOG.info(
            "Archive game: game start: %s, inning start: %s",
            str(broadcast_start_timestamp),
            inning_timestamp_str,
        )
        offset_secs = inning_start_timestamp - broadcast_start_timestamp
        if stream_start_offset_secs != 0:
            LOG.info(
                "Applying stream start offset: %s seconds", stream_start_offset_secs
            )
            offset_secs -= stream_start_offset_secs

        LOG.debug(
            "inning_start_timestamp: %s, broadcast_start_timestamp: %s, offset=%s",
            inning_start_timestamp,
            broadcast_start_timestamp,
            offset_secs,
        )
        logstr = "Calculated archive game inning offset (from start): %s"

    hours, remainder_secs = divmod(offset_secs, 3600)
    minutes, secs = divmod(remainder_secs, 60)
    offset = "{:02d}:{:02d}:{:02d}".format(int(hours), int(minutes), int(secs))
    LOG.info(logstr, offset)
    return offset
