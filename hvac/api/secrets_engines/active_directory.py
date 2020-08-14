#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Active Directory methods module."""

from hvac import utils
from hvac.api.vault_api_base import VaultApiBase

DEFAULT_MOUNT_POINT = 'ad'


class ActiveDirectory(VaultApiBase):
    """Active Directory Secrets Engine (API).
    Reference: https://www.vaultproject.io/api/secret/ad/index.html
    """

    def configure(self, binddn=None, bindpass=None, url=None, userdn=None, upndomain=None, ttl=None, max_ttl=None,
                  mount_point=DEFAULT_MOUNT_POINT, *args, **kwargs):
        """Configure shared information for the ad secrets engine.

        Supported methods:
            POST: /{mount_point}/config. Produces: 204 (empty body)

        :param binddn: Distinguished name of object to bind when performing user and group search.
        :type binddn: str | unicode
        :param bindpass: Password to use along with binddn when performing user search.
        :type bindpass: str | unicode
        :param url: Base DN under which to perform user search.
        :type url: str | unicode
        :param userdn: Base DN under which to perform user search.
        :type userdn: str | unicode
        :param upndomain: userPrincipalDomain used to construct the UPN string for the authenticating user.
        :type upndomain: str | unicode
        :param ttl: – The default password time-to-live in seconds. Once the ttl has passed, a password will be rotated the next time it's requested.
        :type ttl: int | str
        :param max_ttl: The maximum password time-to-live in seconds. No role will be allowed to set a custom ttl greater than the max_ttl
            integer number of seconds or Go duration format string.**
        :type max_ttl: int | str
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        params = utils.remove_nones({
            'binddn': binddn,
            'bindpass': bindpass,
            'url': url,
            'userdn': userdn,
            'upndomain': upndomain,
            'ttl': ttl,
            'max_ttl': max_ttl,
        })

        params.update(kwargs)

        api_path = utils.format_url('/v1/{mount_point}/config', mount_point=mount_point)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_config(self, mount_point=DEFAULT_MOUNT_POINT):
        """Read the configured shared information for the ad secrets engine.

        Credentials will be omitted from returned data.

        Supported methods:
            GET: /{mount_point}/config. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        api_path = utils.format_url('/v1/{mount_point}/config', mount_point=mount_point)
        return self._adapter.get(
            url=api_path,
        )

    def create_or_update_role(self, name, service_account_name=None, ttl=None, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint creates or updates the ad role definition.

        :param name: Specifies the name of an existing role against which to create this ad credential.
        :type name: str | unicode
        :param service_account_name: The name of a pre-existing service account in Active Directory that maps to this role.
            This value is required on create and optional on update.
        :type service_account_name: str | unicode
        :param ttl: Specifies the TTL for this role.
            This is provided as a string duration with a time suffix like "30s" or "1h" or as seconds.
            If not provided, the default Vault TTL is used.
        :type ttl: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: ad).
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/{}/roles/{}", mount_point, name)
        params = {
            "name": name,
        }
        params.update(
            utils.remove_nones({
                "service_account_name": service_account_name,
                "ttl": ttl,
            })
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint queries for information about a ad role with the given name.
        If no role exists with that name, a 404 is returned.
        :param name: Specifies the name of the role to query.
        :type name: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: ad).
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/{}/roles/{}", mount_point, name)
        return self._adapter.get(
            url=api_path,
        )

    def list_roles(self, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint lists all existing roles in the secrets engine.
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/{}/roles", mount_point)
        return self._adapter.list(
            url=api_path,
        )

    def delete_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint deletes a ad role with the given name.
        Even if the role does not exist, this endpoint will still return a successful response.
        :param name: Specifies the name of the role to delete.
        :type name: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: ad).
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/{}/roles/{}", mount_point, name)
        return self._adapter.delete(
            url=api_path,
        )

    def list_libraries(self, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint lists all existing libraries in the secrets engine.

        Args:
            mount_point (str, optional): Specifies the place where the secrets engine will be accessible (default: ad)

        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("v1/{}/library", mount_point)
        return self._adapter.list(
            url=api_path
        )

    def read_library(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint queries for information about an AD library with the given name.
        If no role exists with that name, a 404 is returned.
        :param name: Specifies the name of the library to query.
        :type name: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: ad).
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/{}/library/{}", mount_point, name)
        return self._adapter.get(
            url=api_path,
        )

    def create_or_update_library(self, name, service_account_names=None, ttl=None, max_ttl=None, disable_check_in_enforcement=None, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint creates or updates the AD library definition.

        :param name: Specifies the name of a library against which to create this set.
        :type name: str | unicode
        :param service_account_names: List of names of pre-existing service account(s) in Active Directory that maps to this library.
            This value is required on create and optional on update.
        :type service_account_name: list
        :param ttl: Specifies the TTL for this library.
            This is provided as a string duration with a time suffix like "30s" or "1h" or as seconds.
            If not provided, the default Vault TTL is used.
        :type ttl: str | unicode
        :param max_ttl: Specifies maximum amount of time a single check-out lasts before Vault automatically checks it back in.
            This is provided as a string duration with a time suffix like "30s" or "1h" or as seconds.
            If not provided, the default Vault TTL is used.
        :type max_ttl: str | unicode
        :param disable_check_in_enforcement: Disable enforcing that service accounts must be checked in by the entity or client token that checked them out.
            If not provided, the default Vault value is used (false)
        :type disable_check_in_enforcement: bool
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: ad).
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/{}/library/{}", mount_point, name)
        params = {
            "service_account_names": service_account_names,
        }
        params.update(
            utils.remove_nones({
                "ttl": ttl,
                "max_ttl": max_ttl,
                "disable_check_in_enforcement": disable_check_in_enforcement
            })
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def delete_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint deletes an ad library with the given name.
        Even if the library does not exist, this endpoint will still return a successful response.
        :param name: Specifies the name of the library to delete.
        :type name: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: ad).
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/{}/library/{}", mount_point, name)
        return self._adapter.delete(
            url=api_path,
        )

    def get_library_status(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint checks the status of service accounts in the given library
        :param name: Specifies the name of the library to check
        :type name: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: ad).
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/{}/library/{}/status", mount_point, name)
        return self._adapter.get(
            url=api_path
        )

    def check_out_service_account(self, name, ttl=None, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint checks out a service account from the given library
        :param name: Specifies the name of the library to check out an account
        :type name: str | unicode
        :param ttl: Specifies the TTL for this library.
            This is provided as a string duration with a time suffix like "30s" or "1h" or as seconds.
            If not provided, the default Vault TTL is used.
        :type ttl: str | unicode
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: ad).
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/{}/library/{}/check-out", mount_point, name)
        params = {}
        params.update(
            utils.remove_nones({
                "ttl": ttl,
            })
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def check_in_service_account(self, name, service_account_names=None, mount_point=DEFAULT_MOUNT_POINT):
        """This endpoint checks in a service account from the given library. Typically, this must be done by the same entity that checked out the account.
        :param name: Specifies the name of the library to check out an account
        :type name: str | unicode
        :param service_account_names: List of service accounts to check in at the given library.
            May be omitted if only one account is checked out.
        :type ttl: list
        :param mount_point: Specifies the place where the secrets engine will be accessible (default: ad).
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = utils.format_url("/v1/{}/library/{}/check-in", mount_point, name)
        params = {}
        params.update(
            utils.remove_nones({
                "service_account_names": service_account_names,
            })
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )