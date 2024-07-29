import requests
from django.conf import settings


def send_notification(title: str, body: str, **data) -> dict:
    """
    Function which will call fcm api to send push notification to loyalty app users

    :param title: title of the notification
    :type title: String
    :param body: body of the notification
    :type body: String

    :key user_fcms: List of fcm tokens for each user to send the notification
    :key send_type: String which tells if the notification should be sent to all or 
    selected users. Values to be included are either "all" or "selected"

    :return: Dict containing status and message
    :rtype: dict
    """
    send_type = ""
    fcm_tokens = []
    if 'send_type' in data:
        if type(data['send_type']) is str:
            send_type = data['send_type']
        else:
            return {
                "status": "Failed",
                "message": "Wrong type for send key"
            }
    if 'user_fcms' in data:
        if type(data['user_fcms']) is list:
            fcm_tokens = data['user_fcms']
        else:
            return {
                "status": "Failed",
                "message": "Wrong type for user_fcms key"
            }

    firebase_config = getattr(settings, 'FIREBASE_CONFIG', {})
    data = {
        "notification": {
            "body": body,
            "title": title
        }
    }
    header_data = {
        "Content-Type": "application/json",
        "Authorization": firebase_config['auth_key']
    }
    if send_type == "selected":
        data['registration_ids'] = fcm_tokens
    elif send_type == "all":
        data['to'] = firebase_config['topic']

    send_status = requests.post(
        url=firebase_config['url'], json=data, headers=header_data)
    response = send_status.json()
    if send_status.status_code == 200:
        if 'success' in response:
            if response['success'] == 1:
                return {
                    "status": "Success",
                    "message": "Notification sent successfully"
                }
            else:
                return {
                    "status": "Failed",
                    "message": f"Failed to send notification. Message from firebase: {send_status['results']}"
                }
        elif 'message_id' in response:
            return {
                "status": "Success",
                "message": "Notification sent successfully"
            }
        else:
            return {
                "status": "Failed",
                "message": f"Failed to send notification. Message from firebase: {send_status['results']}"
            }
