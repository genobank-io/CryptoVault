# Django Libs
import logging
from django.db import models

from .RSAaddresses import AddressBitcoin

logger = logging.getLogger('django_info')


class AddressQueryset(models.QuerySet):
    ''' Add custom querysets'''

    def check_existence(self, public_key_b64):
        return self.filter(public_key_b64=public_key_b64).exists()

    def get_rsa_address(self, public_key_b64):
        _record = self.filter(public_key_b64=public_key_b64).first()
        return _record.address


class AddressManager(models.Manager):
    ''' Add custom Manager  '''

    def get_queryset(self):
        return AddressQueryset(self.model, using=self._db)

    def check_existence(self, public_key_b64):
        return self.get_queryset().check_existence(public_key_b64)

    def get_rsa_address(self, public_key_b64):
        return self.get_queryset().get_rsa_address(public_key_b64)

    def create_rsa_address(self, public_key_b64):
        ''' Method to create new rsa address '''

        _addresses_generator = AddressBitcoin()
        _new_raw_address = _addresses_generator.create_address_bitcoin(public_key_b64)

        rsa_address = self.create(
            public_key_b64=public_key_b64,
            address=_new_raw_address,
        )
        rsa_address.save()
        return rsa_address.address

    def get_or_create_rsa_address(self, public_key_b64):
        ''' 'Check existence of address for public key '''
        if self.check_existence(public_key_b64):
            ''' Return correct address '''
            return self.get_rsa_address(public_key_b64)
        else:
            ''' Return a new address for the public key '''
            return self.create_rsa_address(public_key_b64)
