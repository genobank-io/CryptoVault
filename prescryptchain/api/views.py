# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# REST
from rest_framework.viewsets import ViewSetMixin
from rest_framework import routers, serializers, viewsets
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.views import APIView
from rest_framework import mixins, generics
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
# our models
from blockchain.models import Block, Prescription, Transaction
from blockchain.utils import pubkey_string_to_rsa, savify_key, pubkey_base64_to_rsa

# Define router
router = routers.DefaultRouter()


class PrescriptionSerializer(serializers.ModelSerializer):
    """ Prescription serializer """
    timestamp = serializers.DateTimeField(read_only=False)
    data = serializers.JSONField(binary=False, read_only=False)

    class Meta:
        model = Prescription
        fields = (
            'id',
            'public_key',
            'data',
            'timestamp',
            'signature',
            'previous_hash',
            'raw_size',
            'hash_id',
            'is_valid',
            'transaction',
            'readable',
        )
        read_only_fields = ('id', 'hash_id', 'previous_hash', 'is_valid',' transaction',)

    def create(self, validated_data):
        return Transaction.objects.create_tx(data=validated_data)


class PrescriptionViewSet(viewsets.ModelViewSet):
    """ Prescription Viewset """
    # Temporally without auth
    # authentication_classes = (TokenAuthentication, BasicAuthentication, )
    # permission_classes = (IsAuthenticated, )
    serializer_class = PrescriptionSerializer

    def get_queryset(self):
        ''' Custom Get queryset '''
        raw_public_key = self.request.query_params.get('public_key', None)
        if raw_public_key:
            try:
                pub_key = pubkey_string_to_rsa(raw_public_key)
            except:
                pub_key , raw_public_key = pubkey_base64_to_rsa(raw_public_key)
            hex_raw_pub_key = savify_key(pub_key)
            return Prescription.objects.filter(public_key=hex_raw_pub_key).order_by('-id')
        else:
            return Prescription.objects.all().order_by('-id')


# add patient filter by email, after could modify with other
router.register(r'rx-endpoint', PrescriptionViewSet, 'prescription-endpoint')


class BlockSerializer(serializers.ModelSerializer):
    """ Prescription serializer """
    class Meta:
        model = Block
        fields = (
            'id',
            'hash_block',
            'previous_hash',
            'raw_size',
            'data',
            'timestamp',
            'merkleroot',
            'hashcash',
            'nonce',
        )
        read_only_fields = ('id', 'hash_block','timestamp','previous_hash', 'raw_size', 'data', 'merkleroot','hashcash','nonce',)


class BlockViewSet(viewsets.ModelViewSet):
    """ Prescription Viewset """
    serializer_class = BlockSerializer

    def get_queryset(self):
        return Block.objects.all().order_by('-timestamp')


# add patient filter by email, after could modify with other
router.register(r'block', BlockViewSet, 'block-endpoint')
