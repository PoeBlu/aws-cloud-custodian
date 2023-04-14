import logging
import six

from abc import ABCMeta, abstractmethod

from c7n.utils import local_session
from c7n_azure.session import Session


@six.add_metaclass(ABCMeta)
class DeploymentUnit:

    def __init__(self, client):
        self.type = ""
        self.session = local_session(Session)
        self.client = self.session.client(client)
        self.log = logging.getLogger('custodian.azure.function_app_utils')

    def get(self, params):
        result = self._get(params)
        if result:
            self.log.info(f"""Found {self.type} "{params['name']}".""")
        else:
            self.log.info(f"""{self.type} "{params['name']}" not found.""")
        return result

    def check_exists(self):
        return self.get() is not None

    def provision(self, params):
        self.log.info(f"""Creating {self.type} "{params['name']}\"""")
        result = self._provision(params)
        if result:
            self.log.info(f"""{self.type} "{params['name']}" successfully created""")
        else:
            self.log.info(f"""Failed to create {self.type} "{params['name']}\"""")
        return result

    def provision_if_not_exists(self, params):
        result = self.get(params)
        if result is None:
            if 'id' in params.keys():
                raise Exception(f"{self.type} with {params['id']} id is not found")
            result = self.provision(params)
        return result

    @abstractmethod
    def _get(self, params):
        raise NotImplementedError()

    @abstractmethod
    def _provision(self, params):
        raise NotImplementedError()
