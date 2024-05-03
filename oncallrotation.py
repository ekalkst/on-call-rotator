import os
import logging
import argparse
import sys
from pdpyras import APISession, PDClientError
from slack_bolt import App
from slack_sdk.errors import SlackApiError

# logging
def setup_logging(log_level):
    """Sets up logging to the console with the specified log level.

    Args:
        log_level (int): Logging level (default: logging.INFO).
    """

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def parse_args():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Script for updating the slack responder for a PagerDuty on call shift"
    )
    parser.add_argument(
        "-s",
        "--schedule_id",
        type=str,
        help="The ID of the schedule in Pagerduty"
    )
    parser.add_argument(
        "-r",
        "--responder_id",
        type=str,
        help="The ID of the slack responder group"
    )
    parser.add_argument(
        "-v",
        "--verbosity",
        choices=["info", "warn", "error", "debug"],
        default="info",
        help="Set the verbosity level",
    )
    args = parser.parse_args()
    return args


def get_on_call_user_id(schedule_id, session):
    """Fetches the ID of the on-call user from PagerDuty."""
    logging.info("Fetching Pagerduty on-call user id:")
    try:
        response = session.jget(f"/oncalls/?schedule_ids%5B%5D={schedule_id}")
        rep = response["oncalls"][0]["user"]["id"]
        logging.info(
            "Sucessfully fetched on-call user id [%s] for %s",
            rep,
            response["oncalls"][0]["user"]["summary"],
        )
        return rep
    except (PDClientError, KeyError) as e:
        logging.error("Error fetching on-call user id: %s", {e})
        sys.exit(1)


def get_on_call_user_email(user_id, session):
    """Fetches the email of the on-call user from PagerDuty."""
    logging.info("Fetching Pagerduty on-call user email for id %s", user_id)
    try:
        resp = session.jget(f"/users/{user_id}")
        logging.info(
            "Succesfully fetched Pagerduty on-call user email [%s] for id %s",
            resp["user"]["email"],
            user_id,
        )
        return resp["user"]["email"]
    except (PDClientError, KeyError) as e:
        logging.error("Error fetching on-call user email: %s", {e})
        sys.exit(1)


def get_slack_id(user_email, app):
    """Fetches the Slack ID of the on-call user."""
    try:
        logging.info("Fetching slack id for %s", user_email)
        slack_id = app.client.users_lookupByEmail(email=user_email)["user"]["id"]
        logging.info("Succesfully fetched slack id %s for %s", [slack_id], user_email)
        return slack_id
    except SlackApiError as e:
        # You will get a SlackApiError if "ok" is False
        logging.error(
            "Failed to fetch slack id %s", {e.response["error"]}
        )  # str like 'invalid_auth', 'channel_not_found'
        sys.exit(1)


def update_responder(responder_id, slack_id, app):
    """Updates the Slack responder for the given schedule with the on-call user's Slack ID."""
    logging.info("Attempting to update slack responder")
    try:
        app.client.usergroups_users_update(usergroup=responder_id, users=slack_id)
        logging.info("Succesfully updated slack responder")
    except SlackApiError as e:
        logging.error(
            "Failed to update slack responder %s", {e.response["error"]}
        )  # str like 'invalid_auth', 'channel_not_found'
        sys.exit(1)

def main():
    """Main entry point for the script."""
    args = parse_args()
    schedule_id = args.schedule_id
    responder_id = args.responder_id
    log_level = args.verbosity
    setup_logging(log_level.upper())
    api_key = os.environ.get("PAGERDUTY_API_KEY")
    if not api_key:
        logging.error(
            "PAGERDUTY_API_KEY is empty. Please set it in env vars."
        )
        sys.exit(1)
    app = App(token=os.environ.get("SLACK_BOT_TOKEN"))
    if not app:
        logging.error(
            "SLACK_BOT_TOKEN is empty. Please set it in env vars."
        )
        sys.exit(1)
    session = APISession(api_key)
    user_id = get_on_call_user_id(schedule_id, session)
    user_email = get_on_call_user_email(user_id, session)
    slack_id = get_slack_id(user_email, app)
    update_responder(responder_id, slack_id, app)


if __name__ == "__main__":
    main()
