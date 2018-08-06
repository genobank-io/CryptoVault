# -*- encoding: utf-8 -*-
from rest_framework.exceptions import APIException

class FailedVerifiedSignature(APIException):
    status_code = 400
    default_detail = 'Fallo el chequeo de la firma, checa tu payload lo creaste bien o si no se enviaron tus datos corruptamente'
    default_code = 'Failed verified Signature'
