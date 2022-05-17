# -*- encoding: utf-8 -*-

"""
Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
Create: 2022-05-16
Content: Common utils module
"""

import logging
import os
import re
from ctypes import cdll, create_string_buffer, c_char_p, c_int, byref, POINTER

from django.contrib.auth import login
from django.http import JsonResponse

from vote.models import User, VoteOption

SHOW_MSG = {
    'login_name_pwd_error': '用户名或密码错误，请重新输入',
    'login_error': '登录失败，请重新尝试登录',
    'login_success': '登录成功',
    'logout_success': '用户退出成功',
    'invalid_request': '无效的用户请求',
    'query_success': '查询投票结果成功',
    'vote_success': '投票成功',
    'vote_failed': '投票失败',
    'duplicate_vote': '用户已投票，请勿重复投票'
}

# CA file location
CA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'libsecret-vote-ca.so')
LOGGER = logging.getLogger('vote')


def validate_username(username):
    """
    Validate username
    :param username
    :return: Match a string starting with a letter, containing letters, data or special characters (-_), length 6-32
    """
    if not isinstance(username, str):
        return False
    regex = '^[a-zA-Z][a-zA-Z0-9_-]{5,31}$'
    match = re.match(regex, username)
    return match is not None


def login_user(request, user):
    """
    Sava user message and send success message to the front end
    :param request: HttpRequest object
    :param user: user specific message
    :return: Login success information
    """
    user = User.objects.get(id=user.id)
    user.set_login_status(True)

    # Call CA method to get public key and sign
    if len(user.get_public_key()) == 0:
        LOGGER.info('User logs in for the first time')
        public_key, sign = generate_public_key_and_sign()
        if len(public_key) == 0:
            LOGGER.error('Failed to call CA GetTaskPubKey method')
            return JsonResponse(status=403, data=new_generate_response_body('login_error'))
        user.set_public_key(public_key)
        user.set_sign(sign)
    user.save()

    # Add user message to current session
    login(request=request, user=user)

    # Return success message
    data = {'id': user.id, 'username': user.get_username()}
    LOGGER.info('Log in successfully')
    return JsonResponse(status=200, data=data)


def check_if_user_login():
    """ Custom decorator: Check if user is logged in """
    def wrapper(func):
        def decorated(request, *args, **kwargs):
            user_id = request.user.id
            if user_id is None:
                return JsonResponse(status=401, data=new_generate_response_body('invalid_request'))
            user = User.objects.get(id=user_id)
            if not request.user.is_authenticated or not user.get_login_status():
                LOGGER.error(f'Invalid request: user authenticated status: {request.user.is_authenticated}, user '
                                f'login status: {user.get_login_status()}')
                return JsonResponse(status=401, data=new_generate_response_body('invalid_request'))
            return func(request, *args, **kwargs)
        return decorated
    return wrapper


def new_generate_response_body(message_title, data=None):
    """
    Generate response message dictionary
    :param message_title: the key value of the prompt information in the dictionary
    :param data: response body raw data
    :return: Response message dictionary
    """
    if not data:
        data = {}
    return {'data': data, 'info_chinese': SHOW_MSG.get(message_title)}


def generate_public_key_and_sign():
    """
    Call CA method to generate public key and related sign
    This method is only called when the user logs in for the first time
    :return: Public key and related sign
    """
    ca = cdll.LoadLibrary(CA_PATH)
    ca.GetTaskPubKey.argtypes = [c_char_p, c_int, c_char_p, c_int]
    ca.GetTaskPubKey.restype = c_int
    key_buf = create_string_buffer(4096)
    sign_buf = create_string_buffer(4096)
    result = ca.GetTaskPubKey(key_buf, 4096, sign_buf, 4096)
    if result != 0:
        key_buf = ''
        sign_buf = ''
    return bytes(key_buf), bytes(sign_buf)


def assemble_vote_data(user_vote_status):
    """
    Assemble vote data
    :param user_vote_status: user vote status
    :return: Vote data
    """
    vote_info_list = []
    vote_option_list = VoteOption.objects.all()

    # Assemble vote summary data
    if user_vote_status is True:
        LOGGER.info('Send vote statistics to the front end')
        for vote_option in vote_option_list:
            data = {
                'vote_id': vote_option.get_option_id(),
                'vote_opt_message': vote_option.get_vote_opt_message(),
                'votes_number': vote_option.get_votes_number()}
            vote_info_list.append(data)
    else:
        LOGGER.info('Send vote option content to the front end')
        for vote_option in vote_option_list:
            data = {
                'vote_id': vote_option.get_option_id(),
                'vote_opt_message': vote_option.get_vote_opt_message()}
            vote_info_list.append(data)

    # Assemble vote data
    vote_data = {
        'vote_status': user_vote_status,
        'vote_title': VoteOption.VOTE_TITLE,
        'vote_sub_title': VoteOption.VOTE_SUB_TITLE,
        'vote_info_list': vote_info_list}
    return vote_data


def send_vote_msg(user, vote_id):
    """
    Send vote message to CA
    :param user: User object
    :param vote_id: vote option id
    """
    # Get CA method arguments
    public_key = user.get_public_key().encode()
    sign = user.get_sign().encode()
    username = user.get_username().encode()
    vote_result = c_int(0)

    # Call CA vote method
    ca = cdll.LoadLibrary(CA_PATH)
    ca.Vote.argtypes = [c_char_p, c_int, c_char_p, c_int, c_char_p, c_int, c_int, POINTER(c_int)]
    ca.Vote.restype = c_int
    result = ca.Vote(public_key, 4096, sign, 4096, username, len(username), c_int(vote_id), byref(vote_result))
    if result != 0:
        vote_result = -1
    return vote_result.value
