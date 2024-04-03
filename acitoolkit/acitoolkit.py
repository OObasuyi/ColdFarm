###############################################################################
#                                  _    ____ ___                              #
#                                 / \  / ___|_ _|                             #
#                                / _ \| |    | |                              #
#                               / ___ \ |___ | |                              #
#                         _____/_/   \_\____|___|_ _                          #
#                        |_   _|__   ___ | | | _(_) |_                        #
#                          | |/ _ \ / _ \| | |/ / | __|                       #
#                          | | (_) | (_) | |   <| | |_                        #
#                          |_|\___/ \___/|_|_|\_\_|\__|                       #
#                                                                             #
###############################################################################
#                                                                             #
# Copyright (c) 2015 Cisco Systems                                            #
# All Rights Reserved.                                                        #
#                                                                             #
#    Licensed under the Apache License, Version 2.0 (the "License"); you may  #
#    not use this file except in compliance with the License. You may obtain  #
#    a copy of the License at                                                 #
#                                                                             #
#        http://www.apache.org/licenses/LICENSE-2.0                           #
#                                                                             #
#    Unless required by applicable law or agreed to in writing, software      #
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT#
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the #
#    License for the specific language governing permissions and limitations  #
#    under the License.                                                       #
#                                                                             #
###############################################################################
"""  Main aci_mod Toolkit module
     This is the main module that comprises the aci_mod Toolkit.
"""
try:
    # Python <=3.9
    from collections import Sequence
except ImportError:
    # Python > 3.8
    from collections.abc import Sequence

import logging
from operator import attrgetter, itemgetter
import re
import sys
import copy

from requests.compat import urlencode
from requests.exceptions import ConnectionError

from .acibaseobject import BaseACIObject, BaseInterface, _Tag
from .aciphysobject import Interface, Fabric
from .acisession import Session


log = logging.getLogger(__name__)


class Tenant(BaseACIObject):
    """
    The Tenant class is used to represent the tenants within the acitoolkit
    object model.  In the APIC model, this class is roughly equivalent to
    the fvTenant class.
    """

    def __init__(self, name, parent=None):
        """
        :param name: String containing the Tenant name
        :param parent: None or An instance of Fabric class representing the Pod
                       which contains this Tenant.
        """
        if parent is not None and not isinstance(parent, Fabric) and not isinstance(parent, LogicalModel):
            raise TypeError('Parent must be None or an instance of Fabric class. Parent given as %s' % type(parent))
        super(Tenant, self).__init__(name, parent)

    @classmethod
    def _get_apic_classes(cls):
        """
        Get the APIC classes used by this acitoolkit class.

        :returns: list of strings containing APIC class names
        """
        return ['fvTenant']

    @staticmethod
    def _get_parent_class():
        """
        Gets the class of the parent object

        :returns: class of parent object
        """
        return LogicalModel

    def _get_instance_subscription_urls(self):
        url = '/api/mo/uni/tn-{}.json?subscription=yes'.format(self.name)
        return [url]

    @staticmethod
    def _get_name_dn_delimiters():
        return ['/tn-', '/']

    def get_json(self):
        """
        Returns json representation of the fvTenant object

        :returns: A json dictionary of fvTenant
        """
        attr = self._generate_attributes()
        return super(Tenant, self).get_json(self._get_apic_classes()[0],
                                            attributes=attr)

    def push_to_apic(self, session):
        """
        Push the appropriate configuration to the APIC for this Tenant.
        All of the subobject configuration will also be pushed.

        :param session: the instance of Session used for APIC communication
        :returns: Requests Response code
        """
        resp = session.push_to_apic(self.get_url(),
                                    self.get_json())
        return resp

    def _get_url_extension(self):

        rn = self._get_name_dn_delimiters()[0] + self.name
        return rn

    @classmethod
    def _get_toolkit_to_apic_classmap(cls):
        """
        Gets the APIC class to an acitoolkit class mapping dictionary

        :returns: dict of APIC class names to acitoolkit classes
        """
        return {'fvAp': AppProfile,
                'fvBD': BridgeDomain,
                'vzCPIf': ContractInterface,
                'fvCtx': Context,
                'vzBrCP': Contract,
                'vzFilter': Filter,
                'vzTaboo': Taboo,
                'l3extOut': OutsideL3}

    @classmethod
    def get_deep(cls, session, names=(), limit_to=(), subtree='full', config_only=False, parent=None):
        """
        Get the Tenant objects and all of the children objects.

        :param session: the instance of Session used for APIC communication
        :param names: list of strings containing the tenant names. If no list is given, all tenants will be collected.
                      It should be noted that if relations extend across tenants, the relation will only be
                      populated if the tenants are included in this list.
        :param limit_to: list of strings containing the APIC classes to limit the collection to i.e. ['fvTenant',
                         'fvBD']. If no list is given, all classes will be collected.
        :param subtree: String containing the rsp-subtree option. Default is 'full'.
        :param config_only: Boolean containing whether to collect only configurable parameters
        :param parent: The parent instance to assign to the tenant objects. If None, a Fabric instance will be created.
        :returns: Requests Response code
        """
        resp = []
        if isinstance(names, str) or \
                not isinstance(names, Sequence) or \
                not all(isinstance(name, str) for name in names):
            raise TypeError('names should be a Sequence of strings')
        names = list(names) or [tenant.name for tenant in Tenant.get(session)]
        if isinstance(limit_to, str) or \
                not isinstance(limit_to, Sequence) or \
                not all(isinstance(class_name, str) for class_name in limit_to):
            raise TypeError('limit_to should be a Sequence of strings')
        limit_to = list(limit_to)
        if 'common' in names:
            # If tenant common is part of the list, put it at the front so we populate that first
            names.remove('common')
            names.insert(0, 'common')
        params = {'query-target': 'self', 'rsp-subtree': subtree}
        if len(limit_to):
            params['rsp-subtree-class'] = ','.join(limit_to)
        if config_only:
            params['rsp-prop-include'] = 'config-only'
        query = urlencode(params)
        objs = []
        full_data = []
        if parent is None:
            parent = Fabric()
        for name in names:
            query_url = '/api/mo/uni/tn-{}.json?{}'.format(name, query)
            ret = session.get(query_url)

            # the following works around a bug encountered in the json returned from the APIC
            # Python3 throws an error 'TypeError: 'str' does not support the buffer interface'
            # This error gets catched and the replace is done with byte code in a Python3 compatible way
            try:
                ret._content = ret._content.replace("\\\'", "'")
            except TypeError:
                ret._content = ret._content.replace(b"\\\'", b"'")

            data = ret.json()['imdata']
            if len(data):
                full_data.append(data[0])
                obj = super(Tenant, cls).get_deep(full_data=data,
                                                  working_data=data,
                                                  parent=parent,
                                                  limit_to=limit_to,
                                                  subtree=subtree,
                                                  config_only=config_only)
                if obj is not None:
                    objs.append(obj)
                    resp.append(obj)
                else:
                    print(name, 'resulted in a null object')
        obj_dict = build_object_dictionary(objs)
        for obj in objs:
            obj._extract_relationships(full_data, obj_dict)
        return resp

    @classmethod
    def get(cls, session, parent=None):
        """
        Gets all of the tenants from the APIC.

        :param parent: Parent object of the Tenant
        :param session: the instance of Session used for APIC communication
        :returns: a list of Tenant objects
        """
        tenants = BaseACIObject.get(session, cls, cls._get_apic_classes()[0])

        if parent:
            if isinstance(parent, LogicalModel):
                for tenant in tenants:
                    parent.add_child(tenant)
        return tenants

    @classmethod
    def exists(cls, session, tenant):
        """
        Check if a tenant exists on the APIC.

        :param session: the instance of Session used for APIC communication
        :param tenant: the instance of Tenant to check if exists on the APIC
        :returns: True or False
        """
        apic_tenants = cls.get(session)
        return any(apic_tenant == tenant for apic_tenant in apic_tenants)

    @staticmethod
    def get_url(fmt='json'):
        """
        Get the URL used to push the configuration to the APIC
        if no format parameter is specified, the format will be 'json'
        otherwise it will return '/api/mo/uni.' with the format string
        appended.

        :param fmt: optional format string, default is 'json'
        :returns: URL string
        """
        return '/api/mo/uni.' + fmt

    @staticmethod
    def get_table(tenants, title=''):
        """
        Will create table of switch context information

        :param title:
        :param tenants:
        """

        headers = ['Tenant', 'Description']
        data = []
        for tenant in sorted(tenants):
            data.append([
                tenant.name,
                tenant.descr])

        data = sorted(data)
        table = Table(data, headers, title=title + 'Tenant')
        return [table, ]

		
class AppProfile(BaseACIObject):
    """
    The AppProfile class is used to represent the Application Profiles within
    the acitoolkit object model.  In the APIC model, this class is roughly
    equivalent to the fvAp class.
    """

    def __init__(self, name, parent):
        """
        :param name: String containing the Application Profile name
        :param parent: An instance of Tenant class representing the Tenant\
                       which contains this Application Profile.
        """
        if not isinstance(parent, Tenant):
            raise TypeError('Parent must be of Tenant class')
        super(AppProfile, self).__init__(name, parent)

    @classmethod
    def _get_apic_classes(cls):
        """
        Get the APIC classes used by this acitoolkit class.

        :returns: list of strings containing APIC class names
        """
        return ['fvAp']

    @classmethod
    def _get_toolkit_to_apic_classmap(cls):
        """
        Gets the APIC class to an acitoolkit class mapping dictionary

        :returns: dict of APIC class names to acitoolkit classes
        """
        return {'fvAEPg': EPG, }

    @staticmethod
    def _get_parent_class():
        """
        Gets the class of the parent object

        :returns: class of parent object
        """
        return Tenant

    @staticmethod
    def _get_name_dn_delimiters():
        return ['/ap-', '/']

    def _get_instance_subscription_urls(self):
        url = '/api/mo/uni/tn-%s/ap-%s.json?subscription=yes' % (self._parent.name, self.name)
        return [url]

    @classmethod
    def _get_name_from_dn(cls, dn):
        if '/LDevInst-' in dn or '/lDev-' in dn:
            return 'ServiceGraph'
        elif '/ap-' not in dn:
            return None
        name = dn.split('/ap-')[1].split('/')[0]
        return name

    def get_json(self):
        """
        Returns json representation of the AppProfile object.

        :returns: json dictionary of fvAp
        """
        attr = self._generate_attributes()
        return super(AppProfile, self).get_json(self._get_apic_classes()[0],
                                                attributes=attr)

    @classmethod
    def get(cls, session, tenant):
        """Gets all of the Application Profiles from the APIC.

        :param session: the instance of Session used for APIC communication
        :param tenant: the instance of Tenant used to limit the Application\
                       Profiles retreived from the APIC
        :returns: List of AppProfile objects
        """
        return BaseACIObject.get(session, cls, cls._get_apic_classes()[0],
                                 parent=tenant, tenant=tenant)


    @staticmethod
    def get_table(app_profiles, title=''):
        """
        Will create table of app_profile information for a given tenant

        :param title:
        :param app_profiles:
        """
        result = []
        headers = ['Tenant', 'App Profile', 'Description',
                   'EPGs']

        by_name = attrgetter('name')
        for app_profile in sorted(app_profiles, key=by_name):
            data = []
            for epg in sorted(app_profile.get_children(EPG), key=by_name):
                data.append([
                    app_profile.get_parent().name,
                    app_profile.name,
                    app_profile.descr,
                    epg.name,
                ])
            result.append(Table(data, headers, title=title + 'Application Profile: {0}'.format(app_profile.name)))
        return result


class CommonEPG(BaseACIObject):
    """
    Base class for EPG and OutsideEPG.
    Not meant to be instantiated directly
    """

    def __init__(self, epg_name, parent=None):
        """
        :param epg_name: String containing the name of this EPG
        :param parent: Instance of the AppProfile class representing\
                       the Application Profile where this EPG is contained.
        """
        super(CommonEPG, self).__init__(epg_name, parent)

    # Contract references
    def provide(self, contract):
        """
        Make this EPG provide a Contract

        :param contract: Instance of Contract class to be provided by this EPG.
        :returns: True
        """
        if self.does_provide(contract):
            return True
        self._add_relation(contract, 'provided')
        return True

    def does_provide(self, contract):
        """
        Check if this EPG provides a specific Contract.

        :param contract: Instance of Contract class to check if it is\
                         provided by this EPG.
        :returns: True or False.  True if the EPG does provide the Contract.
        """
        return self._has_relation(contract, 'provided')

    def dont_provide(self, contract):
        """
        Make this EPG not provide a Contract

        :param contract: Instance of Contract class to be no longer provided\
                         by this EPG.
        :returns: True
        """
        self._remove_relation(contract, 'provided')

    def get_all_provided(self, deleted=False):
        """
        Get all of the Contracts provided by this EPG

        :param deleted: Boolean indicating whether to get Contracts that are provided
                        or that the provided was marked as deleted
        :returns: List of Contract objects that are provided by the EPG.
        """
        if deleted:
            return self._get_all_detached_relation(Contract, 'provided')
        else:
            return self._get_all_relation(Contract, 'provided')

    def consume(self, contract):
        """
        Make this EPG consume a Contract

        :param contract: Contract class instance to be consumed by this EPG.
        :returns: True
        """

        if self.does_consume(contract):
            return True
        self._add_relation(contract, 'consumed')
        return True

    def does_consume(self, contract):
        """
        Check if this EPG consumes a specific Contract

        :param contract: Instance of Contract class to check if it is\
                         consumed by this EPG.
        :returns: True or False.  True if the EPG does consume the Contract.
        """
        return self._has_relation(contract, 'consumed')

    def dont_consume(self, contract):
        """
        Make this EPG not consume a Contract.  It does not check to see
        if the Contract was already consumed

        :param contract: Instance of Contract class to be no longer consumed\
                         by this EPG.
        :returns: True
        """
        self._remove_relation(contract, 'consumed')
        return True

    def get_all_consumed(self, deleted=False):
        """
        Get all of the Contracts consumed by this EPG

        :param deleted: Boolean indicating whether to get Contracts that are consumed
                        or that the consumed was marked as deleted
        :returns: List of Contract objects that are consumed by the EPG.
        """
        if deleted:
            return self._get_all_detached_relation(Contract, 'consumed')
        else:
            return self._get_all_relation(Contract, 'consumed')

    def consume_cif(self, contract_interface):
        """
        Make this EPG consume a ContractInterface

        :param contract_interface: ContractInterface class instance to be consumed by this EPG.
        :returns: True
        """

        if self.does_consume_cif(contract_interface):
            return True
        self._add_relation(contract_interface, 'consumed')
        return True

    def does_consume_cif(self, contract_interface):
        """
        Check if this EPG consumes a specific Contract

        :param contract_interface:
        :returns: True or False.  True if the EPG does consume the ContractInterface.
        """
        return self._has_relation(contract_interface, 'consumed')

    def dont_consume_cif(self, contract_interface):
        """
        Make this EPG not consume a ContractInterface.  It does not check to see
        if the ContractInterface was already consumed

        :param contract_interface:
        :returns: True
        """
        self._remove_relation(contract_interface, 'consumed')
        return True

    def get_all_consumed_cif(self, deleted=False):
        """
        Get all of the ContractInterfaces consumed by this EPG

        :param deleted: Boolean indicating whether to get ContractInterfaces that
                        are consumed or that the consumed was marked as deleted
        :returns: List of ContractInterface objects that are consumed by the EPG.
        """
        if deleted:
            return self._get_all_detached_relation(ContractInterface, 'consumed')
        else:
            return self._get_all_relation(ContractInterface, 'consumed')

    def protect(self, taboo):
        """
        Make this EPG protected by a Taboo

        :param taboo: Instance of Taboo class to protect this EPG.
        :returns: True
        """
        if self.does_protect(taboo):
            return True
        self._add_relation(taboo, 'protected')
        return True

    def does_protect(self, taboo):
        """
        Check if this EPG is protected by a specific Taboo.

        :param taboo: Instance of Taboo class to check if it protects
                         this EPG.
        :returns: True or False.  True if the EPG is protected by the Taboo.
        """
        return self._has_relation(taboo, 'protected')

    def dont_protect(self, taboo):
        """
        Make this EPG not protected by a Taboo

        :param taboo: Instance of Taboo class to no longer protect\
                         this EPG.
        :returns: True
        """
        self._remove_relation(taboo, 'protected')

    def get_all_protected(self, deleted=False):
        """
        Get all of the Taboos protecting this EPG

        :param deleted: Boolean indicating whether to get Taboos that are protected
                        or that the protected was marked as deleted

        :returns: List of Taboo objects that are protecting the EPG.
        """
        if deleted:
            return self._get_all_detached_relation(Taboo, 'protected')
        else:
            return self._get_all_relation(Taboo, 'protected')

    def get_interfaces(self, status='attached'):
        """
        Get all of the interfaces that this EPG is attached.
        The default is to get list of 'attached' interfaces.
        If 'status' is set to 'detached' it will return the list of
        detached Interface objects (Those EPGs which are no longer
        attached to an Interface, but the configuration is not yet
        pushed to the APIC.)

        :param status: 'attached' or 'detached'.  Defaults to 'attached'.
        :returns: List of Interface objects
        """

        resp = []
        for relation in self._relations:
            if relation.item.is_interface() and relation.status == status:
                resp.append(relation.item)
        return resp

    def _get_common_json(self):
        """Internal routine to generate JSON common to EPGs and Outside EPGs"""
        children = []
        for contract in self.get_all_provided():
            text = {'fvRsProv': {'attributes': {'tnVzBrCPName': contract.name}}}
            children.append(text)
        for contract in self.get_all_consumed():
            text = {'fvRsCons': {'attributes': {'tnVzBrCPName': contract.name}}}
            children.append(text)
        for contract_interface in self.get_all_consumed_cif():
            text = {'fvRsConsIf': {'attributes': {'tnVzCPIfName': contract_interface.name}}}
            children.append(text)
        for taboo in self.get_all_protected():
            text = {'fvRsProtBy': {'attributes': {'tnVzTabooName': taboo.name}}}
            children.append(text)
        for contract in self.get_all_provided(deleted=True):
            text = {'fvRsProv': {'attributes': {'status': 'deleted', 'tnVzBrCPName': contract.name}}}
            children.append(text)
        for contract in self.get_all_consumed(deleted=True):
            text = {'fvRsCons': {'attributes': {'status': 'deleted', 'tnVzBrCPName': contract.name}}}
            children.append(text)
        for contract_interface in self.get_all_consumed_cif(deleted=True):
            text = {'fvRsConsIf': {'attributes': {'status': 'deleted', 'tnVzCPIfName': contract_interface.name}}}
            children.append(text)
        for taboo in self.get_all_protected(deleted=True):
            text = {'fvRsProtBy': {'attributes': {'status': 'deleted', 'tnVzTabooName': taboo.name}}}
            children.append(text)
        return children

    @classmethod
    def get(cls, session, parent=None, tenant=None):
        """Gets all of the EPGs from the APIC.

        :param session: the instance of Session used for APIC communication
        :param parent: Instance of the AppProfile class used to limit the EPGs\
                       retreived from the APIC.
        :param tenant: Instance of Tenant class used to limit the EPGs\
                       retreived from the APIC.
        :returns: List of CommonEPG instances (or EPG instances if called\
                  from EPG class)
        """
        return BaseACIObject.get(session, cls, cls._get_apic_classes()[0],
                                 parent, tenant)


		
class EPG(CommonEPG):
    """ EPG :  roughly equivalent to fvAEPg """

    def __init__(self, epg_name, parent=None):
        """
        Initializes the EPG with a name and, optionally,
        an AppProfile parent.
        If the parent is specified and is not an AppProfile,
        an error will occur.

        :param epg_name: String containing the name of the EPG.
        :param parent: Instance of the AppProfile class representing\
                       the Application Profile where this EPG is contained.
        """
        if parent:
            if not isinstance(parent, AppProfile):
                raise TypeError('Parent must be instance of AppProfile')
        super(EPG, self).__init__(epg_name, parent)
        self._leaf_bindings = []
        self.match_type = None
        self.class_id = None
        self.scope = None
        self._deployment_immediacy = None
        self._intra_epg_isolation = False
        self._dom_deployment_immediacy = None
        self._dom_resolution_immediacy = None
        self._is_attribute_based = False
        self._base_epg = None

    def _generate_attributes(self):
        attributes = super(EPG, self)._generate_attributes()
        if self._is_attribute_based:
            attributes['isAttrBasedEPg'] = 'yes'
        if self._intra_epg_isolation:
            attributes['pcEnfPref'] = 'enforced'
        return attributes

    @property
    def is_attributed_based(self):
        """
        Get whether the EPG is attribute based
        :return: True if attribute based. False otherwise.
        """
        return self._is_attribute_based

    @is_attributed_based.setter
    def is_attributed_based(self, x):
        """
        Set the attribute_based flag.  Indicates that the EPG is attribute based.
        :param x: String containing 'true' or 'yes' indicates that the EPG is attribute based.
        :return: None
        """
        if isinstance(x, str):
            if x.lower() in ['true', 'yes']:
                self._is_attribute_based = True
            else:
                self._is_attribute_based = False
        self._is_attribute_based = x

    def set_base_epg(self, epg):
        """
        Sets the Base EPG.  Used by Attribute-based EPGs to indicate that the BridgeDomain, NodeAttach, and
        PathAttach relations should be copied from the base EPG when generating JSON.

        :param epg: EPG class instance of the Base EPG
        :return: None
        """
        self._base_epg = epg

    @classmethod
    def _get_apic_classes(cls):
        """
        Get the APIC classes used by this acitoolkit class.

        :returns: list of strings containing APIC class names
        """
        return ['fvAEPg']

    @classmethod
    def _get_toolkit_to_apic_classmap(cls):
        """
        Gets the APIC class to an acitoolkit class mapping dictionary

        :returns: dict of APIC class names to acitoolkit classes
        """
        return {'fvCEp': Endpoint,
                'fvStCEp': Endpoint,
                'fvCrtrn': AttributeCriterion}

    @staticmethod
    def _get_parent_class():
        """
        Gets the class of the parent object

        :returns: class of parent object
        """
        return AppProfile

    def _get_instance_subscription_urls(self):
        url = '/api/mo/uni/tn-%s/ap-%s/epg-%s.json?subscription=yes' % (
            self._parent._parent.name, self._parent.name, self.name)
        return [url]

    @staticmethod
    def _get_name_dn_delimiters():
        return ['/epg-', '/']

    @classmethod
    def _get_name_from_dn(cls, dn):
        if '/LDevInst-' in dn or '/lDev-' in dn:
            return 'ServiceGraph'
        elif '/epg-' not in dn:
            return None
        return dn.split('/epg-')[1].split('/')[0]

    def _populate_from_attributes(self, attributes):
        """
        Sets the attributes when creating objects from the APIC.
        Called from the base object when calling the classmethod get()
        """
        super(EPG, self)._populate_from_attributes(attributes)
        if 'matchT' in attributes:
            self.match_type = str(attributes.get('matchT'))
        if 'pcTag' in attributes:
            self.class_id = str(attributes.get('pcTag'))
        if 'scope' in attributes:
            self.scope = str(attributes.get('scope'))
        if 'name' in attributes:
            self.name = str(attributes.get('name'))
        elif self.dn != '':
            self.name = self._get_name_from_dn(self.dn)
        if str(attributes.get('isAttrBasedEPg')).lower() in ['true', 'yes']:
            self._is_attribute_based = True
        else:
            self._is_attribute_based = False
        if attributes.get('pcEnfPref') == 'enforced':
            self._intra_epg_isolation = True
        else:
            self._intra_epg_isolation = False

    # Infrastructure Domain references
    def add_infradomain(self, infradomain):
        """
        Add Infrastructure Domain to the EPG

        :param infradomain:  Instance of InfraDomain class.
        """
        if not isinstance(infradomain, EPGDomain):
            raise TypeError('add_infradomain not called with InfraDomain')
        self.populate_children(True)
        if self.has_child(infradomain):
            return
        self.add_child(infradomain)
        infradomain._add_relation(self)

    # Bridge Domain references
    def add_bd(self, bridgedomain):
        """
        Add BridgeDomain to the EPG, roughly equivalent to fvRsBd

        :param bridgedomain: Instance of BridgeDomain class.  Represents\
                             the BridgeDomain that this EPG will be assigned.\
                             An EPG can only be assigned to a single\
                             BridgeDomain.
        """
        if not isinstance(bridgedomain, BridgeDomain):
            raise TypeError('add_bd not called with BridgeDomain')
        self._remove_all_relation(BridgeDomain)
        self._add_relation(bridgedomain)

    def remove_bd(self):
        """
        Remove BridgeDomain from the EPG.
        Note that there should only be one BridgeDomain attached to the EPG.
        """
        self._remove_all_relation(BridgeDomain)

    def get_bd(self):
        """
        Return the assigned BridgeDomain.
        There should only be one item in the returned list.

        :returns: List of BridgeDomain objects
        """
        return self._get_any_relation(BridgeDomain)

    def has_bd(self):
        """
        Check if a BridgeDomain has been assigned to the EPG

        :returns: True or False.  True if the EPG has been assigned\
                  a BridgeDomain.
        """
        return self._has_any_relation(BridgeDomain)

    def set_deployment_immediacy(self, immediacy):
        """
        Set the deployment immediacy of the EPG

        :param immediacy: String containing either "immediate" or "lazy"
        """
        self._deployment_immediacy = immediacy

    def set_intra_epg_isolation(self, isolation):
        """
        Set the intra-EPG isolation of the EPG

        :param isolation: String containing either "unenforced" or "enforced"
        """
        self._intra_epg_isolation = isolation

    def set_dom_deployment_immediacy(self, immediacy):
        """
        Set the deployment immediacy for PhysDomain of the EPG

        :param immediacy: String containing either "immediate" or "lazy"
        """
        self._dom_deployment_immediacy = immediacy

    def set_dom_resolution_immediacy(self, immediacy):
        """
        Set the resolution immediacy for PhysDomain of the EPG

        :param immediacy: String containing either "immediate" or "lazy"
        """
        self._dom_resolution_immediacy = immediacy

    def _get_all_contracts(self, contract_type, deleted=False, include_any_epg=False):
        """
        Internal common function to get all of the Contracts/Taboos used by this EPG

        :param contract_type: String containing the contract type. Valid values are:
                              'provided', 'consumed'
        :param deleted: Boolean indicating whether to get Contracts that are provided
                        or that the provided was marked as deleted
        :param include_any_epg: Boolean indicating whether to include Contracts that
                                are provided due to inheritance from an AnyEPG within
                                the same Context providing it.
        :returns: List of Contract objects that are provided by the EPG.
        """
        if contract_type not in ['provided', 'consumed']:
            raise ValueError
        resp = []
        if include_any_epg:
            # Check if the tenant context has an AnyEPG
            any_epgs = []
            if self.has_bd() and self.get_bd().has_context():
                any_epgs += self.get_bd().get_context().get_children(only_class=AnyEPG)
            else:
                # Look for AnyEPG in the tenant common Context
                try:
                    my_fabric = self.get_parent().get_parent().get_parent()
                    tenants = my_fabric.get_children(only_class=Tenant)
                    for tenant in tenants:
                        if tenant.name == 'common':
                            common_contexts = tenant.get_children(only_class=Context)
                            for context in common_contexts:
                                if context.name == 'default':
                                    any_epgs += context.get_children(only_class=AnyEPG)
                except AttributeError:
                    # Couldn't find tenant common
                    pass
            for any_epg in any_epgs:
                if contract_type == 'provided':
                    resp += any_epg.get_all_provided(deleted=deleted)
                else:
                    resp += any_epg.get_all_consumed(deleted=deleted)
        if contract_type == 'provided':
            resp += super(EPG, self).get_all_provided(deleted=deleted)
        else:
            resp += super(EPG, self).get_all_consumed(deleted=deleted)
        return resp

    def get_all_provided(self, deleted=False, include_any_epg=False):
        """
        Get all of the Contracts provided by this EPG

        :param deleted: Boolean indicating whether to get Contracts that are provided
                        or that the provided was marked as deleted
        :param include_any_epg: Boolean indicating whether to include Contracts that
                                are provided due to inheritance from an AnyEPG within
                                the same Context that this EPG is in.
        :returns: List of Contract objects that are provided by the EPG.
        """
        return self._get_all_contracts(contract_type='provided',
                                       deleted=deleted,
                                       include_any_epg=include_any_epg)

    def get_all_consumed(self, deleted=False, include_any_epg=False):
        """
        Get all of the Contracts consumed by this EPG

        :param deleted: Boolean indicating whether to get Contracts that are consumed
                        or that the consumed was marked as deleted
        :param include_any_epg: Boolean indicating whether to include Contracts that
                                are consumed due to inheritance from an AnyEPG within
                                the same Context that this EPG is in.
        :returns: List of Contract objects that are consumed by the EPG.
        """
        return self._get_all_contracts(contract_type='consumed',
                                       deleted=deleted,
                                       include_any_epg=include_any_epg)

    def _extract_relationships(self, data, obj_dict):
        app_profile = self.get_parent()
        tenant = app_profile.get_parent()
        for tenant_data in data:
            if 'fvTenant' in tenant_data and tenant_data['fvTenant']['attributes']['name'] == tenant.name:
                tenant_children = tenant_data['fvTenant']['children']
        epg_children = None
        for app in tenant_children:
            if 'fvAp' in app:
                if app['fvAp']['attributes']['name'] == app_profile.name:
                    for epg in app['fvAp']['children']:
                        if 'fvAEPg' in epg:
                            epg_name = epg['fvAEPg']['attributes']['name']
                            if epg_name == self.name:
                                epg_children = epg['fvAEPg']['children']
        for child in epg_children:
            if 'fvRsBd' in child:
                bd_name = child['fvRsBd']['attributes']['tnFvBDName']
                # bd_search = Search()
                # bd_search.name = bd_name
                # objs = tenant.find(bd_search)
                if BridgeDomain in obj_dict:
                    objs = obj_dict[BridgeDomain]
                    found = False
                    for bd in objs:
                        # if isinstance(bd, BridgeDomain):
                        if bd.name == bd_name and bd.get_parent() == tenant:
                            self.add_bd(bd)
                            found = True
                    if not found:
                        for bd in objs:
                            if bd.name == bd_name and bd.get_parent().name == 'common':
                                self.add_bd(bd)

            elif 'fvRsPathAtt' in child:
                int_attributes = child['fvRsPathAtt']['attributes']
                int_dn = int_attributes['tDn']
                if Interface.is_dn_vpc(int_dn):
                    inter = PortChannel.create_from_dn(int_dn)
                else:
                    int_type, pod, node, module, port = Interface.parse_dn(int_dn)
                    inter = Interface(int_type, pod, node, module, port)
                encap = int_attributes['encap']
                encap_type, encap_id = L2Interface.parse_encap(encap)
                encap_mode = int_attributes['mode']
                if Interface.is_dn_vpc(int_dn):
                    l2int = L2Interface('l2_int_{}-{}_on_{}'.format(encap_type, encap_id, inter.name),
                                        encap_type,
                                        encap_id,
                                        encap_mode)
                else:
                    l2int = L2Interface('l2_int_{}-{}_on_{}{}/{}/{}/{}'.format(encap_type, encap_id, int_type,
                                                                               pod, node, module, port),
                                        encap_type,
                                        encap_id,
                                        encap_mode)
                l2int.attach(inter)
                self.attach(l2int)
            elif 'fvRsProv' in child:
                contract_name = child['fvRsProv']['attributes']['tnVzBrCPName']
                # contract_search = Search()
                # contract_search.name = contract_name
                # objs = tenant.find(contract_search)
                # if len(objs):
                #     for contract in objs:
                #         if isinstance(contract, Contract):
                # else:
                #     # Need to check tenant common (if available)
                #     fabric = tenant.get_parent()
                #     if fabric is not None:
                #         tenant_search = Search()
                #         tenant_search.name = 'common'
                #         tenant_common = fabric.find(tenant_search)
                #         if len(tenant_common):
                #             objs = tenant_common[0].find(contract_search)
                #             if len(objs):
                #                 for contract in objs:
                #                     if isinstance(contract, Contract):
                #                         self.provide(contract)

                if Contract in obj_dict:
                    objs = obj_dict[Contract]
                else:
                    objs = []
                if len(objs):
                    found = False
                    for contract in objs:
                        if contract.name == contract_name and contract.get_parent() == tenant:
                            self.provide(contract)
                            found = True
                    if not found:
                        for contract in objs:
                            if contract.name == contract_name and contract.get_parent().name == 'common':
                                self.provide(contract)
            elif 'fvRsCons' in child:
                contract_name = child['fvRsCons']['attributes']['tnVzBrCPName']
                # contract_search = Search()
                # contract_search.name = contract_name
                # objs = tenant.find(contract_search)
                # if len(objs):
                #     for contract in objs:
                #         if isinstance(contract, Contract):
                #             self.consume(contract)
                # else:
                # Need to check tenant common (if available)
                # fabric = tenant.get_parent()
                # if fabric is not None:
                #     tenant_search = Search()
                #     tenant_search.name = 'common'
                #     tenant_common = fabric.find(tenant_search)
                #     if len(tenant_common):
                #         objs = tenant_common[0].find(contract_search)
                #         if len(objs):
                #             for contract in objs:
                #                 if isinstance(contract, Contract):
                #                     self.consume(contract)
                if Contract in obj_dict:
                    objs = obj_dict[Contract]

                    if len(objs):
                        found = False
                        for contract in objs:
                            if contract.name == contract_name and contract.get_parent() == tenant:
                                self.consume(contract)
                                found = True
                        if not found:
                            for contract in objs:
                                if contract.name == contract_name and contract.get_parent().name == 'common':
                                    self.consume(contract)

            elif 'fvRsDomAtt' in child:
                dom_attributes = child['fvRsDomAtt']['attributes']
                dom = EPGDomain(dom_attributes['tDn'], self)
                dom.tDn = dom_attributes['tDn']
                self._dom_deployment_immediacy = dom_attributes['instrImedcy']
                self._dom_resolution_immediacy = dom_attributes['resImedcy']
            elif 'fvRsConsIf' in child:
                contract_if_name = child['fvRsConsIf']['attributes']['tnVzCPIfName']
                if ContractInterface in obj_dict:
                    objs = obj_dict[ContractInterface]

                    if len(objs):
                        found = False
                        for contract_if in objs:
                            if contract_if.name == contract_if_name and contract_if.get_parent() == tenant:
                                self.consume_cif(contract_if)
                                found = True
                        if not found:
                            for contract_if in objs:
                                if contract_if.name == contract_if_name and contract_if.get_parent().name == 'common':
                                    self.consume_cif(contract_if)

        super(EPG, self)._extract_relationships(data, obj_dict)

    def add_static_leaf_binding(self, leaf_id, encap_type, encap_id, encap_mode="regular", immediacy="lazy", pod=1):
        """
        Adds a static leaf binding to this EPG.

        :param leaf_id: Integer containing the node ID (e.g. 101)
        :param encap_type: String containing the encapsulation type.\
        Valid values are 'vlan', 'vxlan', or 'nvgre'.
        :param encap_id: String containing the encapsulation specific\
        identifier representing the virtual L2 network (i.e. for VXLAN,\
        this is the numeric value of the VNID).

        :param encap_mode: String containing the encapsulation mode. Use
        "regular" for normal dot1q tagged traffic, "untagged" for traffic
        reaching the leaf without any dot1q tags, and "native" for
        traffic tagged with a 802.1P tag.

        :param immediacy: String containing either "immediate" or "lazy"
        :param pod: Integer containing the aci_mod Pod where the supplied leaf is located.
        """
        if immediacy not in ('immediate', 'lazy'):
            raise ValueError("Immediacy must be one of 'immediate' or 'lazy'")
        if encap_type not in ('vlan', 'vxlan', 'nvgre'):
            raise ValueError("Encap type must be one of 'vlan', 'vxlan', or 'nvgre'")
        if encap_mode not in ('regular', 'untagged', 'native'):
            raise ValueError("Encap mode must be one of 'regular', 'untagged', or 'native'")
        text = {
            'fvRsNodeAtt': {
                'attributes': {
                    'encap': "%s-%s" % (encap_type, str(encap_id)),
                    'instrImedcy': immediacy,
                    'mode': encap_mode,
                    'tDn': 'topology/pod-%s/node-%s' % (str(pod), str(leaf_id))
                }
            }
        }
        self._leaf_bindings.append(text)

    @staticmethod
    def get_from_json(self, data, parent=None):
        """
        returns a Tenant object from a json
        """
        for child in data['fvAEPg']['children']:
            if 'fvRsCons' in child:
                contract_name = child['fvRsCons']['attributes']['tnVzBrCPName']
                contract = Contract(contract_name)
                self.consume(contract)
            elif 'fvRsProv' in child:
                contract_name = child['fvRsProv']['attributes']['tnVzBrCPName']
                contract = Contract(contract_name)
                self.provide(contract)
            elif 'fvRsPathAtt' in child:
                vlan = child['fvRsPathAtt']['attributes']['encap']
                vlan_intf = L2Interface(name='',
                                        encap_type=vlan.split('-')[0],
                                        encap_id=vlan.split('-')[1])
                self.attach(vlan_intf)
            elif 'fvRsBd' in child:
                bd_name = child['fvRsBd']['attributes']['tnFvBDName']
                if isinstance(parent._parent, Tenant):
                    bds = parent._parent.get_children(BridgeDomain)
                    bd_exist = False
                    for bd in bds:
                        if bd.name == bd_name:
                            self.add_bd(bd)
                            bd_exist = True
                    if not bd_exist:
                        bd = BridgeDomain(bd_name, parent=parent._parent)
                        self.add_bd(bd)
        return super(EPG, self).get_from_json(self, data, parent=parent)

    # Output
    def get_json(self):
        """
        Returns json representation of the EPG

        :returns: json dictionary of the EPG
        """
        children = super(EPG, self)._get_common_json()
        if self.has_bd() or (self._base_epg is not None and self._base_epg.has_bd()):
            if self.has_bd():
                bd_name = self.get_bd().name
            else:
                bd_name = self._base_epg.get_bd().name
            text = {'fvRsBd': {'attributes': {'tnFvBDName': bd_name}}}
            children.append(text)
        # Static leaf bindings
        for leaf_binding in self._leaf_bindings:
            children.append(leaf_binding)
        if self._base_epg is not None:
            for leaf_binding in self._base_epg._leaf_bindings:
                no_encap_leaf_binding = copy.deepcopy(leaf_binding)
                if 'encap' in no_encap_leaf_binding['fvRsNodeAtt']['attributes']:
                    del no_encap_leaf_binding['fvRsNodeAtt']['attributes']['encap']
                no_encap_leaf_binding['fvRsNodeAtt']['attributes']['instrImedcy'] = 'immediate'
                children.append(no_encap_leaf_binding)

        is_interfaces = False
        for interface in self.get_interfaces():
            is_interfaces = True
            encap_text = '%s-%s' % (interface.encap_type,
                                    interface.encap_id)
            text = {'fvRsPathAtt': {'attributes': {'encap': encap_text,
                                                   'tDn': interface._get_path()}}}
            if interface.encap_mode:
                text['fvRsPathAtt']['attributes']['mode'] = interface.encap_mode
            if self._deployment_immediacy:
                text['fvRsPathAtt']['attributes']['instrImedcy'] = self._deployment_immediacy
            children.append(text)

            for ep in interface.get_all_attachments(Endpoint):
                ep_children = []
                for child in self.get_children():
                    ep_children.append({'fvStIp': {'attributes': {'addr': child.ip}, 'children': []}})
                path = interface._get_path()
                ep_children.append({'fvRsStCEpToPathEp': {'attributes': {'tDn': path},
                                                          'children': []}})
                text = {'fvStCEp': {'attributes': {'ip': ep.ip,
                                                   'mac': ep.mac,
                                                   'name': ep.name,
                                                   'encap': encap_text,
                                                   'type': 'silent-host'},
                                    'children': ep_children}}
                if ep.is_deleted():
                    text['fvStCEp']['attributes']['status'] = 'deleted'
                children.append(text)
        if is_interfaces:
            # Only add the all-vlans physical domain if nobody has
            # attached any other domain
            if len(self.get_children(only_class=EPGDomain)) == 0:
                text = {'fvRsDomAtt': {'attributes': {'tDn': 'uni/phys-allvlans'}}}
                children.append(text)

        vmm_domains = self.get_all_attached(VmmDomain)
        if self._base_epg is not None:
            vmm_domains += self._base_epg.get_all_attached(VmmDomain)
        for vmm in vmm_domains:
            text = {'fvRsDomAtt': {'attributes': {'tDn': vmm._get_path(),
                                                  'resImedcy': 'immediate'}}}

            if self._deployment_immediacy:
                text['fvRsDomAtt']['attributes']['instrImedcy'] = self._deployment_immediacy

            children.append(text)
        for interface in self.get_interfaces('detached'):
            text = {'fvRsPathAtt': {'attributes': {'encap': '%s-%s' % (interface.encap_type,
                                                                       interface.encap_id),
                                                   'status': 'deleted',
                                                   'tDn': interface._get_path()}}}
            children.append(text)
        attr = self._generate_attributes()
        return super(EPG, self).get_json(self._get_apic_classes()[0],
                                         attributes=attr,
                                         children=children)

    @staticmethod
    def get_table(epgs, title=''):
        """
        Will create table of EPG information for a given tenant

        :param epgs:
        :param title:
        """

        headers = ['Tenant', 'App Profile', 'EPG',
                   'Context', 'Bridge Domain',
                   'Provides', 'Consumes', 'Scope',
                   'Class ID', 'Match Type',
                   'Deployment Immed.']

        data = []
        for epg in sorted(epgs, key=attrgetter('name')):
            context = 'None'
            bd = 'None'
            if epg.has_bd():
                bd = epg.get_bd().name
                if epg.get_bd().has_context():
                    context = epg.get_bd().get_context().name
            consumes = epg.get_all_consumed()
            provides = epg.get_all_provided()

            index_max = max(len(consumes), len(provides), 1)
            for index in range(index_max):
                if index < len(consumes):
                    consume = consumes[index]
                else:
                    consume = ''

                if index < len(provides):
                    provide = provides[index]
                else:
                    provide = ''

                data.append([
                    epg.get_parent().get_parent().name,
                    epg.get_parent().name,
                    epg.name,
                    context,
                    bd,
                    provide,
                    consume,
                    epg.scope,
                    epg.class_id,
                    epg.match_type,
                    epg._deployment_immediacy,
                ])
        data = sorted(data)
        table = Table(data, headers, title=title + 'EPGs')
        return [table, ]


class Endpoint(BaseACIObject):
    """
    Endpoint class
    """

    def __init__(self, name, parent):
        if not isinstance(parent, EPG):
            raise TypeError('Parent must be of EPG class')
        super(Endpoint, self).__init__(name, parent=parent)
        self.mac = None
        self.ip = None
        self.encap = None
        self.if_name = None
        self.if_dn = []
        self.secondary_ip = []

    @classmethod
    def _get_apic_classes(cls):
        """
        Get the APIC classes used by this acitoolkit class.

        :returns: list of strings containing APIC class names
        """
        return ['fvCEp', 'fvStCEp']

    @classmethod
    def _get_toolkit_to_apic_classmap(cls):
        """
        Gets the APIC class to an acitoolkit class mapping dictionary

        :returns: dict of APIC class names to acitoolkit classes
        """
        return {}

    @staticmethod
    def _get_parent_class():
        """
        Gets the class of the parent object

        :returns: class of parent object
        """
        return EPG

    def _get_instance_subscription_urls(self):
        url = '/api/mo/uni/tn-%s/ap-%s/epg-%s/cep-%s.json?subscription=yes' % (
            self._parent._parent._parent.name, self._parent._parent.name, self._parent.name, self.name)
        return [url]

    @staticmethod
    def _get_parent_dn(dn):
        """
        Get the parent DN

        :param dn: string containing the distinguished name URL
        :return: None
        """
        if '/stcep-' in dn:
            return dn.split('/stcep-')[0]
        else:
            return dn.split('/cep-')[0]

    @classmethod
    def _get_name_from_dn(cls, dn):
        if '/stcep-' in dn:
            name = dn.split('/stcep-')[1].split('-type-')[0]
        elif '/cep-' in dn:
            name = dn.split('/cep-')[1]
        else:
            name = None
        return name

    def get_json(self):
        return None

    def _populate_from_attributes(self, attributes):
        if 'mac' not in attributes:
            return
        super(Endpoint, self)._populate_from_attributes(attributes)
        if 'mac' in attributes:
            self.mac = str(attributes.get('mac'))
        if 'ip' in attributes:
            self.ip = str(attributes.get('ip'))
        if 'encap' in attributes:
            self.encap = str(attributes.get('encap'))
        if 'lcC' in attributes:
            life_cycle = str(attributes.get('lcC'))
        if life_cycle != '':
            self.life_cycle = life_cycle
        if 'type' in attributes:
            self.type = str(attributes.get('type'))

    def _populate_interface_info(self, working_data):
        """
        Populate the interface information for the Endpoint

        :param working_data: JSON dictionary containing the working data
        :return: None
        """
        for item in working_data[0]:
            if 'children' in working_data[0][item]:
                children = working_data[0][item]['children']
                for child in children:
                    for child_item in child:
                        if child_item in ['fvRsCEpToPathEp', 'fvRsStCEpToPathEp']:
                            if child[child_item]['attributes']['state'] != 'formed':
                                continue
                            if_dn = str(child[child_item]['attributes']['tDn'])
                            if 'protpaths' in if_dn:
                                regex = re.search(r'pathep-\[(.+)\]$', if_dn)
                                if regex is not None:
                                    self.if_name = regex.group(1)
                                else:
                                    self.if_name = if_dn
                            elif 'tunnel' in if_dn:
                                self.if_name = if_dn
                            elif 'pathgrp' in if_dn:
                                self.if_name = if_dn
                            else:
                                name = if_dn.split('/')
                                pod = str(name[1].split('-')[1])
                                node = str(name[2].split('-')[1])
                                port_result = re.search(r'pathep-\[eth(.+)\]$', if_dn)
                                if port_result is None:
                                    self.if_name = self.if_dn
                                else:
                                    port = port_result.group(1)
                                    self.if_name = 'eth {0}/{1}/{2}'.format(pod, node, port)

                        if child_item == 'fvIp' or child_item == 'fvStIp':
                            ip_address = str(child[child_item]['attributes']['addr'])
                            self.secondary_ip.append(ip_address)

    @classmethod
    def get_deep(cls, full_data, working_data, parent=None, limit_to=(), subtree='full', config_only=False):
        """
        Gets all instances of this class from the APIC and gets all of the
        children as well.

        :param full_data:
        :param working_data:
        :param parent:
        :param limit_to:
        :param subtree:
        :param config_only:
        """
        obj = None
        for item in working_data:
            for key in item:

                # if an endpoint is static then a dynamic one is also created
                # the following will prevent the dynamic one from being added
                if item[key]['attributes']['lcC'] == 'static' and key == 'fvCEp':
                    continue

                if key in cls._get_apic_classes():
                    attribute_data = item[key]['attributes']
                    name = str(attribute_data['name'])
                    if name == '':
                        name = attribute_data['mac']
                    obj = cls(name, parent)
                    if key == 'fvStCEp':
                        obj.life_cycle = 'static'
                    obj._populate_from_attributes(attribute_data)
                    obj._populate_interface_info(working_data)
                    if 'children' in item[key]:
                        for child in item[key]['children']:
                            for apic_class in child:
                                class_map = cls._get_toolkit_to_apic_classmap()
                                if apic_class not in class_map:
                                    if apic_class == 'tagInst':
                                        obj._tags.append(Tag(str(child[apic_class]['attributes']['name'])))
                                    continue
                                else:
                                    class_map[apic_class].get_deep(full_data=full_data,
                                                                   working_data=[child],
                                                                   parent=obj,
                                                                   limit_to=limit_to,
                                                                   subtree=subtree,
                                                                   config_only=config_only)
        return obj

    @classmethod
    def get_event(cls, session, with_relations=True):
        urls = cls._get_subscription_urls()
        for url in urls:
            if not session.has_events(url):
                continue
            event = session.get_event(url)
            for class_name in cls._get_apic_classes():
                if class_name in event['imdata'][0]:
                    break
            attributes = event['imdata'][0][class_name]['attributes']
            if 'status' in attributes:
                status = str(attributes.get('status'))
            if 'dn' in attributes:
                dn = str(attributes.get('dn'))
            parent = cls._get_parent_from_dn(cls._get_parent_dn(dn))
            if status == 'created' and 'mac' in attributes:
                name = str(attributes.get('mac'))
            else:
                name = cls._get_name_from_dn(dn)
            obj = cls(name, parent=parent)
            obj._populate_from_attributes(attributes)
            if 'modTs' in attributes:
                obj.timestamp = str(attributes.get('modTs'))
            if obj.mac is None:
                obj.mac = name
            try:
                if status == 'deleted':
                    obj.mark_as_deleted()
                elif with_relations:
                    objs = cls.get(session, name)
                    if len(objs):
                        obj = objs[0]
                    else:
                        # Endpoint was deleted before we could process the create
                        # return what we what we can from the event
                        pass
                return obj
            except IndexError:
                continue

    @staticmethod
    def _get(session, endpoint_name, interfaces, endpoints,
             apic_endpoint_class, endpoint_path):
        """
        Internal function to get all of the Endpoints

        :param session: Session object to connect to the APIC
        :param endpoint_name: string containing the name of the endpoint
        :param interfaces: list of interfaces
        :param endpoints: list of endpoints
        :param apic_endpoint_class: class of endpoint
        :param endpoint_path: interface of the endpoint
        :return: list of Endpoints
        """
        # Get all of the Endpoints
        if endpoint_name is None:
            endpoint_query_url = ('/api/node/class/%s.json?query-target=self'
                                  '&rsp-subtree=full' % apic_endpoint_class)
        else:
            endpoint_query_url = ('/api/node/class/%s.json?query-target=self'
                                  '&query-target-filter=eq(%s.mac,"%s")'
                                  '&rsp-subtree=full' % (apic_endpoint_class,
                                                         apic_endpoint_class,
                                                         endpoint_name))
        ret = session.get(endpoint_query_url)
        ep_data = ret.json()['imdata']
        for ep in ep_data:
            if ep[apic_endpoint_class]['attributes']['lcC'] == 'static':
                continue
            if 'children' in ep[apic_endpoint_class]:
                children = ep[apic_endpoint_class]['children']
            else:
                children = []
            ep = ep[apic_endpoint_class]['attributes']
            tenant = Tenant(str(ep['dn']).split('/')[1][3:])
            if '/LDevInst-' in str(ep['dn']):
                unknown = '?' * 10
                app_profile = AppProfile(unknown, tenant)
                epg = EPG(unknown, app_profile)
            else:
                app_profile = AppProfile(str(ep['dn']).split('/')[2][3:],
                                         tenant)
                epg = EPG(str(ep['dn']).split('/')[3][4:], app_profile)
            endpoint = Endpoint(str(ep['name']), parent=epg)
            print(ep)
            quit()
            endpoint.mac = str(ep['mac'])
            endpoint.ip = str(ep.get('ip'))
            endpoint.encap = str(ep['encap'])
            endpoint.timestamp = str(ep['modTs'])
            for child in children:
                if endpoint_path in child:
                    endpoint.if_name = str(child[endpoint_path]['attributes']['tDn'])

                    for interface in interfaces:

                        interface = interface['fabricPathEp']['attributes']
                        interface_dn = str(interface['dn'])

                        if endpoint.if_name == interface_dn:
                            if str(interface['lagT']) == 'not-aggregated':
                                endpoint.if_name = _interface_from_dn(interface_dn).if_name
                            else:
                                endpoint.if_name = interface['name']
                                endpoint.if_dn.append(interface_dn)
                    # endpoint_query_url = '/api/mo/' + endpoint.if_name + '.json'
                    # ret = session.get(endpoint_query_url)

                if 'fvIp' in child:
                    if str(child['fvIp']['attributes']['addr']) != endpoint.ip:
                        endpoint.secondary_ip.append(child['fvIp']['attributes']['addr'])
            endpoints.append(endpoint)
        return endpoints

    @staticmethod
    def get(session, endpoint_name=None):
        """Gets all of the endpoints connected to the fabric from the APIC

        :param endpoint_name:
        :param session: Session instance used to communicate with the APIC. Assumed to be logged in
        """
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')

        # Get all of the interfaces
        interface_query_url = ('/api/node/class/fabricPathEp.json?'
                               'query-target=self')
        ret = session.get(interface_query_url)
        interfaces = ret.json()['imdata']

        endpoints = []
        endpoints = Endpoint._get(session, endpoint_name, interfaces,
                                  endpoints, 'fvCEp', 'fvRsCEpToPathEp')
        endpoints = Endpoint._get(session, endpoint_name, interfaces,
                                  endpoints, 'fvStCEp', 'fvRsStCEpToPathEp')

        return endpoints

    @classmethod
    def get_all_by_epg(cls, session, tenant_name, app_name, epg_name, with_interface_attachments=True):
        """
        Get all of the Endpoints for a specified EPG

        :param session: Session instance used to communicate with the APIC. Assumed to be logged in
        :param tenant_name: String containing the tenant name
        :param app_name: String containing the app name
        :param epg_name: String containing the epg name
        :param with_interface_attachments: Boolean indicating whether interfaces should be attached or not.
                                           True is default.
        :return: List of Endpoint instances
        """
        if with_interface_attachments:
            raise NotImplementedError
        query_url = ('/api/mo/uni/tn-%s/ap-%s/epg-%s.json?'
                     'rsp-subtree=children&'
                     'rsp-subtree-class=fvCEp,fvStCEp' % (tenant_name, app_name, epg_name))
        ret = session.get(query_url)
        data = ret.json()['imdata']
        endpoints = []
        if len(data) == 0:
            return endpoints
        assert len(data) == 1
        assert 'fvAEPg' in data[0]
        if 'children' not in data[0]['fvAEPg']:
            return endpoints
        endpoints_data = data[0]['fvAEPg']['children']
        if len(endpoints_data) == 0:
            return endpoints
        tenant = Tenant(tenant_name)
        app = AppProfile(app_name, tenant)
        epg = EPG(epg_name, app)
        for ep_data in endpoints_data:
            if 'fvStCEp' in ep_data:
                mac = ep_data['fvStCEp']['attributes']['mac']
                ip = ep_data['fvStCEp']['attributes']['ip']
            else:
                mac = ep_data['fvCEp']['attributes']['mac']
                ip = ep_data['fvCEp']['attributes']['ip']
            ep = cls(str(mac), epg)
            ep.mac = mac
            ep.ip = ip
            endpoints.append(ep)
        return endpoints

        """
        Will create table of taboo information for a given tenant

        :param title:
        :param endpoints:
        """

        result = []
        headers = ['Tenant', 'Context', 'Bridge Domain', 'App Profile', 'EPG', 'Name', 'MAC', 'IP', 'Interface',
                   'Encap']
        data = []
        for endpoint in sorted(endpoints, key=attrgetter('name')):
            epg = endpoint.get_parent()
            bd = 'Not Set'
            context = 'Not Set'
            if epg.has_bd():
                bd = epg.get_bd().name
                if epg.get_bd().has_context():
                    context = epg.get_bd().get_context().name

            data.append([
                endpoint.get_parent().get_parent().get_parent().name,
                context,
                bd,
                endpoint.get_parent().get_parent().name,
                endpoint.get_parent().name,
                endpoint.name,
                endpoint.mac,
                endpoint.ip,
                endpoint.if_name,
                endpoint.encap
            ])
        data = sorted(data, key=itemgetter(1, 2, 3, 4))
        result.append(Table(data, headers, title=title + 'Endpoints'))
        return result
    def _define_searchables(self):
        """
        Create all of the searchable terms

        :rtype : list of Searchable
        """
        results = super(Endpoint, self)._define_searchables()

        results[0].add_term('ipv4', str(self.ip))
        for secondary_ip in self.secondary_ip:
            results[0].add_term('secondary_ip', secondary_ip)
            results[0].add_term('ipv4', secondary_ip)
        return results


class IPEndpoint(BaseACIObject):
    """
    Endpoint class
    """

    def __init__(self, name, parent):
        # if not isinstance(parent, EPG):
        #     raise TypeError('Parent must be of EPG class')
        super(IPEndpoint, self).__init__(name, parent=parent)
        self.ip = None
        self.mac = None

    @classmethod
    def _get_apic_classes(cls):
        """
        Get the APIC classes used by this acitoolkit class.

        :returns: list of strings containing APIC class names
        """
        return ['fvIp', 'fvStIp']

    @staticmethod
    def _get_parent_class():
        """
        Gets the class of the parent object

        :returns: class of parent object
        """
        return EPG

    @classmethod
    def _get_parent_from_dn(cls, dn):
        """
        Derive the parent object using a dn

        :param dn: String containing a distinguished name of an object
        """
        if '/l2out-' in dn and '/instP-' in dn:
            parent_name = OutsideL2EPG._get_name_from_dn(dn)
            parent_dn = cls._get_parent_dn(dn)
            parent_obj = OutsideL2EPG(parent_name,
                                      OutsideL2EPG._get_parent_from_dn(parent_dn))
            return parent_obj
        return super(IPEndpoint, cls)._get_parent_from_dn(dn)

    @staticmethod
    def _get_name_dn_delimiters():
        return ['/ip-[', ']']

    def get_json(self):
        return None

    def _populate_from_attributes(self, attributes):
        super(IPEndpoint, self)._populate_from_attributes(attributes)
        if 'addr' in attributes:
            self.ip = str(attributes.get('addr'))

    @staticmethod
    def _get_mac_from_dn(dn):
        """
        Extract the MAC address from the dn

        :param dn: string containing the distinguished name URL
        :return: String containing the MAC address or None if not found
        """
        # Handle static IP addresses
        if '/stcep-' in dn:
            return str(dn.split('/stcep-')[1].partition('-type-')[0])
        # Handle dynamic IP addresses
        if '/cep-' in dn:
            return str(dn.split('/cep-')[1].partition('/')[0])
        if '/epdef-' in dn:
            return str(dn.split('/cep-')[1].partition('/')[0])
        return None

    @classmethod
    def get_event(cls, session):
        urls = cls._get_subscription_urls()
        for url in urls:
            if not session.has_events(url):
                continue
            event = session.get_event(url)
            for class_name in cls._get_apic_classes():
                if class_name in event['imdata'][0]:
                    break
            attributes = event['imdata'][0][class_name]['attributes']
            if 'status' in attributes:
                status = str(attributes.get('status'))
            if 'dn' in attributes:
                dn = str(attributes.get('dn'))
            parent = cls._get_parent_from_dn(cls._get_parent_dn(dn))
            name = cls._get_name_from_dn(dn)
            obj = cls(name, parent=parent)
            obj._populate_from_attributes(attributes)
            obj.mac = obj._get_mac_from_dn(dn)
            if status == 'deleted':
                obj.mark_as_deleted()
            return obj

    @staticmethod
    def _get(session, endpoints, apic_endpoint_class):
        """
        Internal function to get all of the IPEndpoints

        :param session: Session object to connect to the APIC
        :param endpoints: list of endpoints
        :param apic_endpoint_class: class of endpoint
        :return: list of Endpoints
        """
        # Get all of the Endpoints
        endpoint_query_url = ('/api/node/class/%s.json?query-target=self'
                              '&rsp-subtree=full' % apic_endpoint_class)
        ret = session.get(endpoint_query_url)
        if not ret.ok:
            raise ConnectionError
        ep_data = ret.json()['imdata']
        for ep in ep_data:
            ep = ep[apic_endpoint_class]['attributes']
            ep_dn = str(ep['dn'])
            ep_addr = str(ep['addr'])
            if not all(x in ep_dn for x in ['/tn-', 'ap-', 'epg-']):
                continue
            tenant = Tenant(ep_dn.split('/')[1][3:])
            app_profile = AppProfile(ep_dn.split('/')[2][3:],
                                     tenant)
            epg = EPG(ep_dn.split('/')[3][4:], app_profile)
            endpoint = IPEndpoint(ep_addr, parent=epg)
            endpoint.ip = ep_addr
            endpoint.mac = IPEndpoint._get_mac_from_dn(ep_dn)
            endpoints.append(endpoint)
        return endpoints

    @staticmethod
    def get(session):
        """Gets all of the IP endpoints connected to the fabric from the APIC

        :param session: Session instance assumed to be logged into the APIC
        :return: List of IPEndpoint instances
        """
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')

        endpoints = []
        endpoints = IPEndpoint._get(session, endpoints, 'fvIp')
        endpoints = IPEndpoint._get(session, endpoints, 'fvStIp')

        return endpoints

    @classmethod
    def get_all_by_epg(cls, session, tenant_name, app_name, epg_name):
        """
        Get all of the IP Endpoints for the specified EPG

        :param session: Session instance assumed to be logged into the APIC
        :param tenant_name: String containing the Tenant name that holds the EPG
        :param app_name: String containing the AppProfile name that holds the EPG
        :param epg_name: String containing the EPG name
        :return: List of IPEndpoint instances
        """
        query_url = ('/api/mo/uni/tn-%s/ap-%s/epg-%s.json?'
                     'query-target=subtree&'
                     'target-subtree-class=fvIp,fvStIp' % (tenant_name, app_name, epg_name))
        ret = session.get(query_url)
        endpoints = []
        if ret.ok:
            ep_data = ret.json()['imdata']
            if len(ep_data) == 0:
                return endpoints
            for ep in ep_data:
                if 'fvStIp' in ep:
                    attr = ep['fvStIp']['attributes']
                elif 'fvIp' in ep:
                    attr = ep['fvIp']['attributes']
                else:
                    log.error('Could not get EPG endpoints from the APIC %s', ep)
                    break
                ep_dn = str(attr['dn'])
                ep_addr = str(attr['addr'])
                if not all(x in ep_dn for x in ['/tn-', 'ap-', 'epg-']):
                    continue
                tenant = Tenant(ep_dn.split('/')[1][3:])
                app_profile = AppProfile(ep_dn.split('/')[2][3:],
                                         tenant)
                epg = EPG(ep_dn.split('/')[3][4:], app_profile)
                endpoint = IPEndpoint(ep_addr, parent=epg)
                endpoint.ip = ep_addr
                endpoint.mac = IPEndpoint._get_mac_from_dn(ep_dn)
                endpoints.append(endpoint)
        else:
            raise ConnectionError
        return endpoints

		
class Search(BaseACIObject):
    """This is an empty class used to create a search object for use with
       the "find" method.

       Attaching attributes to this class and then invoking find will return
       all objects with matching attributes in the object hierarchy at and
       below where the find is invoked.
    """

    def __init__(self):
        pass


class BaseMonitorClass(object):
    """ Base class for monitoring policies.  These are methods that can be
        used on all monitoring objects.
    """

    def set_name(self, name):
        """
        Sets the name of the MonitorStats.

       :param name: String to use as the name
        """
        self.name = str(name)
        self.modified = True

    def set_description(self, description):
        """
        Sets the description of the MonitorStats.

       :param description: String to use as the description
        """
        self.description = description
        self.modified = True

    def isModified(self):
        """
        Returns True if this policy and any children have been modified or
        created and not been written to the APIC
        """
        for child in self._children:
            if child.isModified():
                return True

        return self.modified

    def get_parent(self):
        """
       :returns: parent object
        """
        return self._parent

    def add_stats(self, stat_obj):
        """
        Adds a stats family object.

        :param stat_obj: Statistics family object of type MonitorStats.
        """
        self.monitor_stats[stat_obj.scope] = stat_obj
        self.modified = True

    def remove_stats(self, stats_family):
        """
        Remove a stats family object.  The object to remove is identified by
        a string, e.g. 'ingrPkts', or 'egrTotal'.  This string can be found
        in the 'MonitorStats.scope' attribute of the object.

        :param stats_family: Statistics family string.
        """
        if not isinstance(stats_family, str):
            raise TypeError('MonitorStats must be identified by a string')

        if stats_family in self.monitor_stats:
            self.monitor_stats.remove(stats_family)
            self.modified = True

    def add_target(self, target_obj):
        """
        Add a target object.

        :param target_obj: target object of type MonitorTarget
        """
        self.monitor_target[target_obj.scope] = target_obj
        self.modified = True

    def remove_target(self, target):
        """
        Remove a target object.  The object to remove is identified by
        a string, e.g 'l1PhysIf'.  This string can be found
        in the 'MonitorTarget.scope' attribute of the object.

        :param target: target to remove.
        """
        if not isinstance(target, str):
            raise TypeError('MonitorTarget must be identified by a string')

        if target in self.monitor_target:
            self.monitor_target.remove(target)
            self.modified = True

    def add_collection_policy(self, coll_obj):
        """
        Add a collection policy.

        :param coll_obj:  A collection policy object of type CollectionPolicy
        """
        self.collection_policy[coll_obj.granularity] = coll_obj
        self.modified = True

    def remove_collection_policy(self, collection):
        """
        Remove a collection_policy object.  The object to remove is identified
        by its granularity, e.g. '5min', '15min', etc.  This string can be
        found in the 'CollectionPolicy.granularity' attribute of the object.

        :param collection: CollectionPolicy to remove.
        """
        if collection not in CollectionPolicy.granularityEnum:
            raise TypeError(('CollectionPolicy must be identified by its'
                             'granularity'))

        if collection in self.collection_policy:
            self.collection_policy.remove(collection)
            self.modified = True


class MonitorPolicy(BaseMonitorClass):
    """
    This class is the top-most container for a monitoring policy that controls
    how statistics are gathered. It has immediate children, CollectionPolicy
    objects, that control the default behavior for any network element that
    uses this monitoring policy.  It may optionally have MonitorTarget objects
    as children that are used to override the default behavior for a particular
    target class such as Interfaces.  There can be further granularity of
    control through children of the MonitorTarget sub-objects.

    Children of the MonitorPolicy will be CollectionPolicy objects that define
    the collection policy plus optional MonitorTarget objects that allow finer
    grained control over specific target APIC objects such as 'l1PhysIf' (layer
    1 physical interface).

    The CollectionPolicy children are contained in a dictionary called
    "collection_policy" that is indexed by the granulariy of the
    CollectionPolicy, e.g. '5min', '15min', etc.

    The MonitorTarget children are contained in a dictionary called
    "monitor_target" that is indexed by the name of the target object,
    e.g. 'l1PhysIf'.

    To make a policy take effect for a particular port, for example, you must
    attach that monitoring policy to the port.

    Note that the name of the MonitorPolicy is used to construct the dn of the
    object in the APIC.  As a result, the name cannot be changed.  If you read
    a policy from the APIC, change the name, and write it back, it will create
    a new policy with the new name and leave the old, original policy, in place
    with its original name.

    A description may be optionally added to the policy.
    """

    def __init__(self, policyType, name):
        """
        The MonitorPolicy is initialized with simply a policy type and a name.
        There are two policy types: 'fabric' and 'access'.  The 'fabric'
        monitoring policies can be applied to certain MonitorTarget types and
        'access' monitoring policies can be applied to other MonitorTarget
        types. Initially however, both policies can have l1PhysIf as targets.

        A name must be specified because it is used to build the distinguising
        name (dn) along with the policyType in the APIC.  The dn for "fabric"
        policies will be /uni/fabric/monfabric-[name] and for "access" policies
        it will be /uni/infra/moninfra-[name] in the APIC.

        :param policyType:  String specifying whether this is a fabric or\
                            access policy
        :param name:        String specifying a name for the policy.
        """
        policyTypeEnum = ['fabric', 'access']

        if policyType not in policyTypeEnum:
            raise ValueError('Policy Type must be one of:', policyTypeEnum)

        self.name = name
        self.policyType = policyType
        self.descr = ''
        self.collection_policy = {}
        self.monitor_target = {}

        # assume that it has not been written to APIC.  This is cleared if the
        # policy is just loaded from APIC or the policy is written to the APIC.
        self.modified = True

    @classmethod
    def get(cls, session):
        """
        get() will get all of the monitor policies from the APIC and return
        them as a list.  It will get both fabric and access (infra) policies
        including default policies.

       :param session: the instance of Session used for APIC communication
       :returns: List of MonitorPolicy objects
        """
        result = []
        aciObjects = cls._getClass(session, 'monInfraPol')
        for data in aciObjects:
            name = str(data['monInfraPol']['attributes']['name'])
            policyObject = MonitorPolicy('access', name)
            policyObject.set_description(data['monInfraPol']['attributes']['descr'])
            cls._getPolicy(policyObject, session,
                           data['monInfraPol']['attributes']['dn'])
            result.append(policyObject)

        aciObjects = cls._getClass(session, 'monFabricPol')
        for data in aciObjects:
            name = str(data['monFabricPol']['attributes']['name'])
            policyObject = MonitorPolicy('fabric', name)
            policyObject.set_description(data['monFabricPol']['attributes']['descr'])
            cls._getPolicy(policyObject, session,
                           data['monFabricPol']['attributes']['dn'])
            result.append(policyObject)
        return result

    @staticmethod
    def _getClass(session, aciClass):
        """
        Get the class from the APIC

        :param session: Session object instance
        :param aciClass: string containing classname
        :return: JSON dictionary containing class instances
        """
        prefix = '/api/node/class/'
        suffix = '.json?query-target=self'
        class_query_url = prefix + aciClass + suffix
        ret = session.get(class_query_url)
        data = ret.json()['imdata']
        return data

    @classmethod
    def _getPolicy(cls, policyObject, session, dn):
        """
        Get the policy

        :param policyObject: policyObject
        :param session: Session class instance
        :param dn: string containing the distinguished name
        :return: None
        """
        children = cls._getChildren(session, dn)
        for child in children:
            if child[0] == 'statsHierColl':
                granularity = str(child[1]['attributes']['granularity'])
                adminState = str(child[1]['attributes']['adminState'])
                retention = str(child[1]['attributes']['histRet'])
                collPolicy = CollectionPolicy(policyObject, granularity,
                                              retention, adminState)
                collPolicy.set_name(child[1]['attributes']['name'])
                collPolicy.set_description(child[1]['attributes']['descr'])

            if child[0] in ['monFabricTarget', 'monInfraTarget']:
                scope = str(child[1]['attributes']['scope'])

                # initially only l1PhysIf is supported as a target
                if scope == 'l1PhysIf':
                    target = MonitorTarget(policyObject, scope)
                    target.set_name(str(child[1]['attributes']['name']))
                    target.set_description(str(child[1]['attributes']['descr']))
                    dn = child[1]['attributes']['dn']
                    targetChildren = cls._getChildren(session, dn)
                    for targetChild in targetChildren:
                        if targetChild[0] == 'statsReportable':
                            scope = str(targetChild[1]['attributes']['scope'])
                            scope = MonitorStats.statsDictionary[scope]
                            statFamily = MonitorStats(target, scope)
                            child_attr = targetChild[1]['attributes']
                            statFamily.set_name(str(child_attr['name']))
                            statFamily.set_description(str(child_attr['name']))
                            dn = targetChild[1]['attributes']['dn']
                            statChildren = cls._getChildren(session, dn)
                            for statChild in statChildren:
                                if statChild[0] == 'statsColl':
                                    child_stats = statChild[1]['attributes']
                                    granularity = str(child_stats['granularity'])
                                    adminState = str(child_stats['adminState'])
                                    retention = str(child_stats['histRet'])
                                    collPolicy = CollectionPolicy(statFamily,
                                                                  granularity,
                                                                  retention,
                                                                  adminState)
                                    collPolicy.set_name(child_stats['name'])
                                    collPolicy.set_description(child_stats['descr'])
                        if targetChild[0] == 'statsHierColl':
                            child_attr = targetChild[1]['attributes']
                            granularity = str(child_attr['granularity'])
                            adminState = str(child_attr['adminState'])
                            retention = str(child_attr['histRet'])
                            collPolicy = CollectionPolicy(target,
                                                          granularity,
                                                          retention,
                                                          adminState)
                            collPolicy.set_name(child_attr['name'])
                            collPolicy.set_description(child_attr['descr'])

    @classmethod
    def _getChildren(cls, session, dn):
        """
        Get the children

        :param session: Session instance object
        :param dn: string containing the distinguished name
        :return: json dictionary containing the children objects
        """
        result = []
        mo_query_url = '/api/mo/' + dn + '.json?query-target=children'
        ret = session.get(mo_query_url)
        mo_data = ret.json()['imdata']
        for node in mo_data:
            for key in node:
                result.append((key, node[key]))
        return result

    def __str__(self):
        """
        Return print string.
        """
        return self.policyType + ':' + self.name

    def flat(self, target='l1PhysIf'):
        """
        This method will return a data structure that is a flattened version
        of the monitor policy. The flattened version is one that walks through
        the heirarchy of the policy and determines the administrative state and
        retention policy for each granularity of each statistics family.
        This is done for the target specified, i.e. 'l1PhysIf'

        For example, if 'foo' is a MonitorPolicy object, then
        flatPol = foo.flat('l1PhysIf') will return a dictionary that looks like
        the following:

        adminState = flatPol['counter_family']['granularity'].adminState
        retention = flatPol['counter_family']['granularity'].retention

        The dictionary will have all of the counter families for all of the
        granularities and the value returned is the administrative state and
        retention value that is the final result of resolving the policy
        hierarchy.

        :param target:  APIC target object.  This will default to 'l1PhysIf'
        :returns: Dictionary of statistic administrative state and retentions
                  indexed by counter family and granularity.
        """

        class Policy(object):
            """
            Policy class
            """

            def __init__(self):
                self.adminState = 'disabled'
                self.retention = 'none'

        result = {}

        # initialize data structure
        for statFamily in MonitorStats.statsFamilyEnum:
            result[statFamily] = {}
            for granularity in CollectionPolicy.granularityEnum:
                result[statFamily][granularity] = Policy()

        # walk through the policy heirarchy and over-ride each
        # policy with the more specific one

        for granularity in self.collection_policy:
            retention = self.collection_policy[granularity].retention
            adminState = self.collection_policy[granularity].adminState
            for statFamily in MonitorStats.statsFamilyEnum:
                result[statFamily][granularity].adminState = adminState
                result[statFamily][granularity].retention = retention

        # now go through monitor targets
        targetPolicy = self.monitor_target[target]
        for granularity in targetPolicy.collection_policy:
            retention = targetPolicy.collection_policy[granularity].retention
            adminState = targetPolicy.collection_policy[granularity].adminState
            for statFamily in MonitorStats.statsFamilyEnum:
                if adminState != 'inherited':
                    result[statFamily][granularity].adminState = adminState
                if retention != 'inherited':
                    result[statFamily][granularity].retention = retention

        target_stats = targetPolicy.monitor_stats
        for statFamily in target_stats:
            collection_pol = target_stats[statFamily].collection_policy
            for granularity in collection_pol:
                retention = collection_pol[granularity].retention
                adminState = collection_pol[granularity].adminState

                if adminState != 'inherited':
                    result[statFamily][granularity].adminState = adminState
                if retention != 'inherited':
                    result[statFamily][granularity].retention = retention

        # if the lesser granularity is disabled, then the larger granularity
        # is as well
        for statFamily in MonitorStats.statsFamilyEnum:
            disable_found = False
            for granularity in CollectionPolicy.granularityEnum:
                if result[statFamily][granularity].adminState == 'disabled':
                    disable_found = True
                if disable_found:
                    result[statFamily][granularity].adminState = 'disabled'
        return result


class MonitorTarget(BaseMonitorClass):
    """
    This class is a child of a MonitorPolicy object. It is used to specify a
    scope for appling a monitoring policy.  An example scope would be the
    Interface class, meaning that the monitoring policies specified here will
    apply to all Interface clas objects (l1PhysIf in the APIC) that use the
    parent MonitoringPolicy as their monitoring policy.

    Children of the MonitorTarget will be CollectionPolicy objects that define
    the collection policy for the specified target plus optional MonitorStats
    objects that allow finer grained control over specific families of
    statistics such as ingress packets, ingrPkts.

    The CollectionPolicy children are contained in a dictionary called
    "collection_policy" that is indexed by the granularity of the
    CollectionPolicy, e.g. '5min', '15min', etc.

    The MonitorStats children are contained in a dictionary called
    "monitor_stats" that is indexed by the name of the statistics family,
    e.g. 'ingrBytes', 'ingrPkts', etc.
    """

    def __init__(self, parent, target):
        """
        The MonitorTarget object is initialized with a parent of type
        MonitorPolicy, and a target string. Initially, this toolkit only
        supports a target of type 'l1PhysIf'.  The 'l1PhyIf' target is a layer
        1 physical interface or "port".  The MonitorTarget will narrow the
        scope of the policy specified by the children of the MonitorTarget to
        be only the target class.

       :param parent:  Parent object that this monitor target is a child.
                       It must be of type MonitorPolicy
       :param target:  String specifying the target class for the Monitor
                       policy.
        """
        targetEnum = ['l1PhysIf']
        if not type(parent) in [MonitorPolicy]:
            raise TypeError(('Parent of MonitorTarget must be one of type'
                             ' MonitorPolicy'))
        if target not in targetEnum:
            raise ValueError('target must be one of:', targetEnum)

        self._parent = parent
        self.scope = target
        self.descr = ''
        self.name = ''
        self._parent.add_target(self)
        self.collection_policy = {}
        self.monitor_stats = {}
        # assume that it has not been written to APIC.
        # This is cleared if the policy is just loaded from APIC
        # or the policy is written to the APIC.
        self.modified = True

    def __str__(self):
        return self.scope


class MonitorStats(BaseMonitorClass):
    """
    This class is a child of a MonitorTarget object.  It is used to specify
    a scope for applying a monitoring policy that is more fine grained than
    the MonitorTarget.  Specifically, the MonitorStats object specifies a
    statistics family such as "ingress packets" or "egress bytes".
    """
    statsDictionary = {'eqptEgrBytes': 'egrBytes',
                       'eqptEgrPkts': 'egrPkts',
                       'eqptEgrTotal': 'egrTotal',
                       'eqptEgrDropPkts': 'egrDropPkts',
                       'eqptIngrBytes': 'ingrBytes',
                       'eqptIngrPkts': 'ingrPkts',
                       'eqptIngrTotal': 'ingrTotal',
                       'eqptIngrDropPkts': 'ingrDropPkts',
                       'eqptIngrUnkBytes': 'ingrUnkBytes',
                       'eqptIngrUnkPkts': 'ingrUnkPkts',
                       'eqptIngrStorm': 'ingrStorm'}

    statsFamilyEnum = ['egrBytes', 'egrPkts', 'egrTotal', 'egrDropPkts',
                       'ingrBytes', 'ingrPkts', 'ingrTotal', 'ingrDropPkts',
                       'ingrUnkBytes', 'ingrUnkPkts', 'ingrStorm']

    def __init__(self, parent, statsFamily):
        """
        The MonitorStats object must always be initialized with a parent object
        of type MonitorTarget. It sets the scope of its children collection
        policies (CollectionPolicy) to a particular statistics family.

        The MonitorStats object contains a dictionary of collection policies
        called collection_policy.  This is a dictionary of children
        CollectionPolicy objects indexed by their granularity, e.g. '5min',
        '15min', etc.

       :param parent: Parent object that this monitor stats object should be\
                      applied to. This must be an object of type MonitorTarget.
       :param statsFamily: String specifying the statistics family that the\
                           children collection policies should be applied to.\
                           Possible values are:['egrBytes', 'egrPkts',\
                           'egrTotal', 'egrDropPkts', 'ingrBytes', 'ingrPkts',\
                           'ingrTotal', 'ingrDropPkts', 'ingrUnkBytes',\
                           'ingrUnkPkts', 'ingrStorm']
        """
        if not type(parent) in [MonitorTarget]:
            raise TypeError(('Parent of MonitorStats must be one of type '
                             'MonitorTarget'))
        if statsFamily not in MonitorStats.statsFamilyEnum:
            raise ValueError('statsFamily must be one of:', MonitorStats.statsFamilyEnum)

        self._parent = parent
        self.scope = statsFamily
        self.descr = ''
        self.name = ''
        self._parent.add_stats(self)
        self.collection_policy = {}
        # assume that it has not been written to APIC.  This is cleared if
        # the policy is just loaded from APIC or the policy is written to
        # the APIC.
        self.modified = True

    def __str__(self):
        return self.scope


class CollectionPolicy(BaseMonitorClass):
    """
    This class is a child of a MonitorPolicy object, MonitorTarget object or
    a MonitorStats object.  It is where the statistics collection policy is
    actually specified.  It applies to all of the statistics that are at the
    scope level of the parent object,
    i.e. all, specific to a target, or specific to a statistics family.  What
    is specified in the CollectionPolicy is the time granularity of the
    collection and how much history to retain.  For example, the granularity
    might be 5 minutes (5min) or 1 hour (1h).  How much history to retain is
    similarly specified.  For example you might specify that it be kept for
    10 days (10d) or 2 years (2year).

    If the CollectionPolicy is a child of a MonitorStats object, it can
    optionally have children that specify the policy for raising threshold
    alarms on the fields in the stats family specified in the MonitorStats
    object.  This has yet to be implemented.

    This object is roughly the same as the statsColl and statsHierColl objects
    in the APIC.
    """
    # this must be in order from small to large
    granularityEnum = ['5min', '15min', '1h', '1d',
                       '1w', '1mo', '1qtr', '1year']
    retentionEnum = ['none', 'inherited', '5min', '15min', '1h', '1d',
                     '1w', '10d', '1mo', '1qtr', '1year', '2year', '3year']

    def __init__(self, parent, granularity, retention, adminState='enabled'):
        """
        The CollectionPolicy must always be initialized with a parent object of
        type MonitorPolicy, MonitorTarget or MonitorStats. The granularity must
        also be specifically specified.  The retention period can be specified,
        set to "none", or set to "inherited".
        Note that the "none" value is a string, not the Python None.  When the
        retention period is set to "none" there will be no historical stats
        kept. However, assuming collection is enabled, stats will be kept for
        the current time period.

        If the retention period is set to "inherited", the value will be
        inherited from the less specific policy directly above this one. The
        same applies to the adminState value.  It can be 'disabled', 'enabled',
        or 'inherited'.  If 'disabled', the current scope of counters are not
        gathered.  If enabled, they are gathered.  If 'inherited', it will be
        according to the next higher scope.

        Having the 'inherited' option on the retention and administrative
        status allows these items independently controlled at the current
        stats granularity.  For example, you can specify that ingress unknown
        packets are gathered every 15 minutes by setting adding a collection
        policy that specifies a 15 minutes granularity and an adminState of
        'enabled' under a MonitorStats object that sets the scope to be ingress
        unknown packets.  This might override a higher level policy that
        disabled collection at a 15 minute interval.   However, you can set the
        retention in that same object to be "inherited" so that this specific
        policy does not change the retention behavior from that of the higher,
        less specific, policy.

        When the CollectionPolicy is a child at the top level, i.e. of the
        MonitorPolicy, the 'inherited' option is not allowed because there
        is no higher level policy to inherit from.  If this were to happen,
        'inherited' will be treated as 'enabled'.

       :param parent: Parent object that this collection policy should be
                      applied to. This must be an object of type MonitorStats,
                      MonitorTarget, or MonitorPolicy.
       :param granularity:  String specifying the time collection interval or
                            granularity of this policy.  Possible values are:
                            ['5min', '15min', '1h', '1d', '1w', '1mo', '1qtr',
                            '1year'].
       :param retention: String specifying how much history to retain the
                         collected statistics for.  The retention will be for
                         time units of the granularity specified.  Possible
                         values are ['none', 'inherited', '5min', '15min',
                         '1h', '1d', '1w', '10d', '1mo', '1qtr', '1year',
                         '2year', '3year'].
       :param adminState:  Administrative status.  String to specify whether
                           stats should be collected at the specified
                           granularity.  Possible values are ['enabled',
                           'disabled', 'inherited'].  The default if not
                           specified is 'enabled'.
        """
        adminStateEnum = ['enabled', 'disabled', 'inherited']

        if type(parent) not in [MonitorStats, MonitorTarget, MonitorPolicy]:
            raise TypeError(('Parent of collection policy must be one of '
                             'MonitorStats, MonitorTarget, or MonitorPolicy'))
        if granularity not in CollectionPolicy.granularityEnum:
            raise ValueError('granularity must be one of:',
                             CollectionPolicy.granularityEnum)
        if retention not in CollectionPolicy.retentionEnum:
            raise ValueError('retention must be one of:',
                             CollectionPolicy.retentionEnum)
        if adminState not in adminStateEnum:
            raise ValueError('adminState must be one of:',
                             CollectionPolicy.adminStateEnum)

        self._parent = parent
        self.granularity = granularity

        self.retention = retention
        self.adminState = adminState
        self._children = []

        self._parent.add_collection_policy(self)
        # assume that it has not been written to APIC.  This is cleared if
        # the policy is just loaded from APIC or the policy is written to
        # the APIC.
        self.modified = True

    def __str__(self):
        return self.granularity

    def setAdminState(self, adminState):
        """
        Sets the administrative status.

        :param adminState:  Administrative status.  String to specify whether
                            stats should be collected at the specified
                            granularity.  Possible values are ['enabled',
                            'disabled', 'inherited'].  The default if not
                            specified is 'enabled'.
        """
        if self.adminState != adminState:
            self.modified = True

        self.adminState = adminState

    def setRetention(self, retention):
        """
        Sets the retention period.

       :param retention: String specifying how much history to retain the
                         collected statistics for.  The retention will be for
                         time units of the granularity specified.  Possible
                         values are ['none', 'inherited', '5min', '15min',
                         '1h', '1d', '1w', '10d', '1mo', '1qtr', '1year',
                         '2year', '3year'].
        """
        if self.retention != retention:
            self.modified = True

        self.retention = retention


class Tag(_Tag):
    """
    Tag class.
    """
    @classmethod
    def get(cls, session, parent=None, tenant=None):
        """Gets all of the Tags from the APIC.

        :param session: the instance of Session used for APIC communication
        :param parent: Instance of the possible Tag parent classes used to limit the Tags\
                       retreived from the APIC.
        :param tenant: Instance of Tenant class used to limit the Tags\
                       retreived from the APIC.
        :returns: List of Tag instances
        """
        return BaseACIObject.get(session, cls, cls._get_apic_classes()[0],
                                 parent=parent, tenant=tenant,query_target_type='children')
    @staticmethod
    def _get_parent_class():
        """
        Gets the class of the parent object

        :returns: class of parent object
        """
        return [EPG, Contract, Tenant, OutsideEPG, OutsideL2, OutsideL3, BridgeDomain, Context, Filter]


class LogicalModel(BaseACIObject):
    """
    This is the root class for the logical part of the network.  Its corollary is the PhysicalModel class.
    It is a container that can hold all of logical model instances such as Tenants.

    From this class, you can populate all of the children classes.
    """

    def __init__(self, session=None, parent=None):
        """
        Initialization method that sets up the Fabric.
        :return:
        """
        if session:
            assert isinstance(session, Session)

        # if parent:
        #     assert isinstance(parent, Fabric)

        super(LogicalModel, self).__init__(name='', parent=parent)

        self._session = session
        self.dn = 'logical'

    @staticmethod
    def _get_parent_class():
        """
        Gets the class of the parent object

        :returns: class of parent object
        """
        return Fabric

    @classmethod
    def _get_name_from_dn(cls, dn):
        """
        Parse the name out of a dn string.
        Meant to be overridden by inheriting classes.
        Raises exception if not overridden.

        :returns: string containing name
        """
        return None

    @staticmethod
    def _get_parent_dn(dn):
        """
        Gets the dn of the parent object
        Meant to be overridden by inheriting classes.
        Raises exception if not overridden.

        :returns: string containing dn
        """
        return None

    @classmethod
    def get(cls, session=None, parent=None):
        """
        Method to get all of the LogicalModels.  It will get one and return it in a list.

        :param session:
        :param parent:
        :return: list of LogicalModel
        """
        logical_model = LogicalModel(session=session, parent=parent)
        return [logical_model]

    @staticmethod
    def _get_children_classes():
        """
        Get the acitoolkit class of the children of this object.
        This is meant to be overridden by any inheriting classes that have children.
        If they don't have children, this will return an empty list.
        :return: list of classes
        """
        return [Tenant]

    @classmethod
    def _get_apic_classes(cls):
        """
        Get the APIC classes used by the acitoolkit class.
        Meant to be overridden by inheriting classes.
        Raises exception if not overridden.

        :returns: list of strings containing APIC class names
        """
        return []

    def populate_children(self, deep=False, include_concrete=False):
        """
        Populates all of the children and then calls populate_children\
        of those children if deep is True.  This method should be\
        overridden by any object that does have children.

        If include_concrete is True, then if the object has concrete objects
        below it, i.e. is a switch, then also populate those conrete object.

        :param include_concrete: True or False. Default is False
        :param deep: True or False.  Default is False.
        """
        for child_class in self._get_children_classes():
            if deep:
                child_class.get_deep(self._session, parent=self)
            else:
                child_class.get(self._session, self)

        return self._children

    def _define_searchables(self):
        """
        Create all of the searchable terms

        """
        results = super(LogicalModel, self)._define_searchables()
        results[0].add_term('model', 'logical')

        return results


def build_object_dictionary(objs):
    """
    Will build a dictionary indexed by object class that contains all the objects of that class

    :param objs:
    :return:
    """
    result = {}
    for obj in objs:
        obj_class = obj.__class__
        if obj_class not in result:
            result[obj_class] = set()

        result[obj_class].add(obj)
        children = obj.get_children()
        children_result = build_object_dictionary(children)
        for child_class in children_result:
            if child_class not in result:
                result[child_class] = set()
            result[child_class] = result[child_class] | children_result[child_class]
    return result

	
def _interface_from_dn(dn):
    """
    Creates the appropriate interface object based on the dn
    The classes along with an example DN are shown below
    Interface: topology/pod-1/paths-102/pathep-[eth1/12]
    FexInterface: topology/pod-1/paths-103/extpaths-105/pathep-[eth1/12]
    TunnelInterface:
    BladeSwitchInterface:
    """
    interface_pattern = r'''(?x)
        topology/pod-(?P<pod>\d+)/paths-(?P<node>\d+)/
        (?:extpaths-(?P<fex>\d+)/)? # optional fex path fragment
        pathep-
        \[
        (?: # physical interface or tunnel
            (?P<if_type>[A-Za-z]{3})(?P<module>\d+)/(?P<port>\d+)
        |
            tunnel(?P<tunnel>\w+)
        )
        \]
    '''
    match = re.match(interface_pattern, dn)
    if not match:
        # Look for Fex interfaces encoded as topology/pod-1/node-101/sys/phys-[eth101/1/1]
        if FexInterface.is_dn_a_fex_interface(dn):
            return FexInterface(*FexInterface.parse_dn(dn))
        return Interface(*Interface.parse_dn(dn))
    elif match.group('fex') is not None:
        args = match.group('if_type', 'pod', 'node', 'fex', 'module', 'port')
        return FexInterface(*args)
    elif match.group('tunnel') is not None:
        args = match.group('pod', 'node', 'tunnel')
        return TunnelInterface('tunnel', *args)
    else:
        return Interface(*Interface.parse_dn(dn))

