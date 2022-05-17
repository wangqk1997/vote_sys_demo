# -*- encoding: utf-8 -*-

"""
Copyright: Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
Create: 2022-05-16
Content: vote_system customize command
"""
import logging

from django.contrib.sessions.models import Session
from django.core.management import BaseCommand

from vote.models import User, VoteOption

LOGGER = logging.getLogger('vote')


def clear_db():
    """ Clear all related database data """
    User.objects.all().delete()
    VoteOption.objects.all().delete()
    Session.objects.all().delete()
    LOGGER.info('Clear database successfully')


def init_user_db():
    """ Initialize user database """
    for user_number in range(10):
        user = User()
        user.id = user_number
        user.set_username('user_0' + str(user_number))
        user.set_password('123456789')
        user.save()
    LOGGER.info('Initialize user data successfully')


def init_vote_option_db():
    """ Initialize vote option database """
    vote_option_msg_list = ['非常满意', '很满意', '一般', '很不满意', '非常不满意']
    for vote_id in range(5):
        vote_opt = VoteOption()
        vote_opt.id = vote_id
        vote_opt.set_option_id(vote_id)
        vote_opt.set_vote_opt_message(vote_option_msg_list[vote_id])
        vote_opt.save()
    LOGGER.info('Initialize vote data successfully')


class Command(BaseCommand):
    """ Custom command to initialize the database """
    def handle(self, *args, **options):
        clear_db()
        init_user_db()
        init_vote_option_db()
        LOGGER.info('All data initialized successfully')
        