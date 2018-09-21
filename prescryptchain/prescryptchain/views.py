# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
from django.shortcuts import render
from django.utils import timezone

from blockchain.models import Prescription, Block, Transaction


def home(request):
    ''' Home view'''
    logger = logging.getLogger('django_info')
    LIMIT_SEARCH = 10
    LIMIT_BLOCK = 5
    _now = timezone.now()

    context = {
        "prescriptions" : Prescription.objects.all().order_by('-id')[:LIMIT_SEARCH],
        "rx_blocks": Block.objects.all().order_by('-id')[:LIMIT_BLOCK],
        "TOTAL_GENOMIC_DATA": Prescription.objects.all().count(),
        "TX_BY_YEAR": Transaction.objects.tx_by_year(_now).count(),
        "TX_BY_MONTH": Transaction.objects.tx_by_month(_now).count(),
    }

    return render(request, "home.html", context)


def block_detail(request, block_hash):
    return render(request, "blockchain/block_detail.html", {})

def rx_detail(request, rx_hash):
    return render(request, "blockchain/rx_detail.html", {})

def humanstxt(request):
    ''' Show humans txt file '''
    response = render(request, 'humans.txt', {})
    response['Content-Type'] = "text/plain"
    return response

