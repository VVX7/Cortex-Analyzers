#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# AGPL-V3
# Copyright (C) 2020 Roger Johnston

import requests
import re
import json
import traceback

import logging
import sys

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


from cortexutils.responder import Responder
from pymisp import ExpandedPyMISP, MISPEvent, MISPTag, MISPAttribute
from thehive4py.api import TheHiveApi


class MISP(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.thehive_url = self.get_param(
            'config.thehive_url', None, "TheHive URL missing.")
        self.thehive_secret = self.get_param(
            'config.thehive_secret', None, "TheHive api key missing.")
        self.misp_url = self.get_param(
            'config.misp_url', None, "MISP URL missing.")
        self.misp_secret = self.get_param(
            'config.misp_secret', None, "MISP api key missing.")
        # Tags we don't want to send to MISP.
        self.filtered_tags = self.get_param(
            'config.filtered_tags', None, "Filtered tags are missing.")
        # Set up TheHive4Py client.
        self.thehive_client = TheHiveApi(url=self.thehive_url, principal=self.thehive_secret)
        # Set up PyMISP client.
        self.misp_client = ExpandedPyMISP(url=self.misp_url, key=self.misp_secret)
        # TheHive case ID we're working on.
        self.thehive_case_id = self.get_param('data.id', None)
        # MISP event we're working on.
        self.misp_event_id = ""
        self.misp_event = None
        # Create MISP Galaxy maps
        self.amitt_map = self.get_amitt_galaxy()
        self.attack_map = self.get_attack_galaxy()

    def is_tag_filtered(self, tag):
        """
        Checks if the provided tag is present in a filter list.
        """
        if tag in self.filtered_tags.split(","):
            return True
        return False

    def return_tlp(self, tlp):
        """
        Reads the TLP from TheHive Case and returns the equivalent MISP Tag name.
        Assign a default TLP:AMBER when no TLP is specified.
        """
        if tlp == 0:
            return "tlp:white"
        elif tlp == 1:
            return "tlp:green"
        elif tlp == 2:
            return "tlp:amber"
        elif tlp == 3:
            return "tlp:red"
        else:
            return "tlp:amber"

    def return_pap(self, tlp):
        """
        Reads the PAP from TheHive Case and returns the equivalent MISP Tag name.
        Assign a default PAP:AMBER when no PAP is specified.
        """
        if tlp == 0:
            return "PAP:WHITE"
        elif tlp == 1:
            return "PAP:GREEN"
        elif tlp == 2:
            return "PAP:AMBER"
        elif tlp == 3:
            return "PAP:RED"
        else:
            return "PAP:AMBER"

    def from_observable(self, data_type, data):
        """
        Converts TheHive Observable date type to corresponding MISP Attribute type.
        https://github.com/TheHive-Project/TheHive/thehive-misp/app/connectors/misp/MispConverter.scala
        """
        if data_type == "filename":
            return "filename"
        elif data_type == "fqdn":
            return "hostname"
        elif data_type == "url":
            return "url"
        elif data_type == "user-agent":
            return "user-agent"
        elif data_type == "domain":
            return "domain"
        elif data_type == "ip":
            return "ip-src"
        elif data_type == "mail_subject":
            return "mail-subject"
        elif data_type == "hash":
            if len(data) == 32:
                return "md5"
            elif len(data) == 40:
                return "sha1"
            elif len(data) == 64:
                return "sha256"
            elif len(data) == 56:
                return "sha224"
            elif len(data) == 71:
                return "sha384"
            elif len(data) == 128:
                return "sha512"
            else:
                return "other"
        elif data_type == "mail":
            return "email-src"
        elif data_type == "registry":
            return "regkey"
        elif data_type == "uri_path":
            return "uri"
        elif data_type == "regexp":
            return "other"
        elif data_type == "other":
            return "other"
        elif data_type == "file":
            return "malware-sample"
        else:
            return "other"

    def get_amitt_galaxy(self):
        """
        Get AMITT Galaxy from MISP.
        """
        amitt_galaxy = self.misp_client.get_galaxy("4d381145-9a5e-4778-918c-fbf23d78544e")
        amitt = {}

        for g in amitt_galaxy["GalaxyCluster"]:
            amitt[g["GalaxyElement"][0]["value"]] = g["tag_name"]
        return amitt

    def get_attack_galaxy(self):
        """
        Get ATT&CK patterns from MISP.
        """
        attack_galaxies = self.misp_client.get_galaxy("c4e851fa-775f-11e7-8163-b774922098cd")
        attack = {}

        for g in attack_galaxies["GalaxyCluster"]:
            attack[g["GalaxyElement"][0]["value"]] = g["tag_name"]
        return attack

    def to_mitre_attack_galaxy(self, attack_map, technique_id):
        """
        Returns a MITRE ATT&CK Galaxy tag.
        """
        t = technique_id.upper()
        if t in attack_map:
            return attack_map[t]
        elif t.split()[0] in attack_map:
            return attack_map[t.split()[0]]
        else:
            return None

    def to_amitt_galaxy(self, amitt_map, technique_id):
        """
        Returns an AMITT Galaxy tag.
        """
        t = technique_id.upper()
        if t in amitt_map:
            return amitt_map[t]
        elif t.split()[0] in amitt_map:
            return amitt_map[t.split()[0]]
        else:
            return None

    def use_misp_event(self, thehive_case):
        """
        Sets the working MISP Event ID if TheHive Case is tagged with a MISP Event ID.
        """
        for thehive_case_tag in thehive_case["tags"]:
            if thehive_case_tag.startswith("MISP:"):
                try:
                    tag = thehive_case_tag.split(":")
                    misp_id = int(tag[1])
                    self.misp_event_id = str(misp_id)
                    return True
                except:
                    return None
        return False

    def add_pap_tag(self, thehive_case):
        """
        Adds a PAP tag to the MISP Event.
        """
        thehive_pap = thehive_case["pap"]
        pap = self.return_pap(thehive_pap)
        pap_tag = MISPTag()
        pap_tag["name"] = pap

        for each_tag in self.misp_event["Tag"]:
            if each_tag.name.startswith("PAP:"):
                self.misp_client.untag(self.misp_event, each_tag)
        self.misp_client.tag(self.misp_event, pap)
        self.misp_event = self.misp_client.get_event(self.misp_event_id, pythonify=True)

    def add_tlp_tag(self, thehive_case):
        """
        Adds a TLP tag to a MISP Event.
        """
        thehive_tlp = thehive_case["tlp"]
        tlp = self.return_tlp(thehive_tlp)
        tlp_tag = MISPTag()
        tlp_tag["name"] = tlp

        for each_tag in self.misp_event["Tag"]:
            if each_tag.name.startswith("tlp:"):
                self.misp_client.untag(self.misp_event, each_tag)
        self.misp_client.tag(self.misp_event, tlp)
        self.misp_event = self.misp_client.get_event(self.misp_event_id, pythonify=True)

    def return_attribute_uuid(self, attribute):
        """
        Returns a MISP Attribute UUID.
        """
        for each_attribute in self.misp_event.attributes:
            if each_attribute.value == attribute["data"]:
                return each_attribute.uuid
        return None

    def create_new_misp_event(self, thehive_case, update, distribution="0"):
        """
        Instantiates a new MISP Event and adds it to MISP.
        """
        # Get TheHive case title.
        thehive_title = thehive_case["title"]
        # Add it to the MISP Event.
        self.misp_event["info"] = thehive_title
        # 0 == Your Org Only
        self.misp_event["distribution"] = distribution
        # Add the event to MISP
        if not update:
            r = self.misp_client.add_event(self.misp_event)
            self.misp_event_id = r["Event"]["id"]
            self.misp_event = self.misp_client.get_event(self.misp_event_id, pythonify=True)
        else:
            self.misp_client.update_event(event=self.misp_event, event_id=self.misp_event_id)

    def add_hive_tags_to_attribute(self, observable, misp_attribute):
        """
        Add Hive Observable tags to MISP.
        """
        if observable["tags"]:
            for hive_tag in observable["tags"]:
                # Ignore filtered tags.
                if not self.is_tag_filtered(hive_tag):
                    # Add this tag to the MISP Attribute.
                    misp_tag = MISPTag()
                    misp_tag["name"] = self.return_tag(hive_tag)
                    misp_attribute["Tag"].append(misp_tag)
        return misp_attribute

    def update_attribute_hive_tags(self, observable, misp_attribute_uuid):
        """
        Update Observable tags in an existing MISP Event.
        """
        if observable["tags"]:
            for hive_tag in observable["tags"]:
                # Ignore filtered tags.
                if not self.is_tag_filtered(hive_tag):
                    # Add this tag to the MISP Attribute.
                    self.misp_client.tag(misp_attribute_uuid, self.return_tag(hive_tag))

    def return_tag(self, thehive_case_tag):
        """
        Returns a Galaxy Tag if it maps to a MISP Galaxy, else returns the tag arg.
        """
        amitt_tag = self.to_amitt_galaxy(self.amitt_map, thehive_case_tag)
        attack_tag = self.to_mitre_attack_galaxy(self.attack_map, thehive_case_tag)
        if amitt_tag:
            return amitt_tag
        elif attack_tag:
            return attack_tag
        else:
            return thehive_case_tag

    def add_hive_case_tags_to_misp_event(self, thehive_case):
        """
        Adds Hive Case Tags to a MISP Event.
        """
        # Add TheHive Case tags.
        for thehive_case_tag in thehive_case["tags"]:
            if not self.is_tag_filtered(thehive_case_tag):
                # Add this tag to the MISP Attribute.
                misp_tag = MISPTag()
                misp_tag["name"] = self.return_tag(thehive_case_tag)
                self.misp_event["Tag"].append(misp_tag)

        self.misp_client.update_event(event=self.misp_event, event_id=self.misp_event_id)
        self.misp_event = self.misp_client.get_event(self.misp_event_id, pythonify=True)

    def new_misp_attribute(self, observable):
        """
        Instantiates a new MISP Attribute from a Hive Observable.
        """
        # Build a MISP attribute.
        misp_attribute = MISPAttribute()
        # Add TheHive Observables tags as MIPS tags.
        # We're going to apply a filter to remove unwanted tags (such as those used for app integrations).
        misp_attribute = self.add_hive_tags_to_attribute(observable, misp_attribute)
        # Determine the MISP Attribute types to use.
        data_type = self.from_observable(observable["dataType"], observable["data"])
        # Add the MISP Attribute to the MISP Event.
        misp_attribute["type"] = data_type
        misp_attribute["value"] = observable["data"]
        return misp_attribute

    def run(self):
        """
        Do the thing.
        """
        try:
            Responder.run(self)

            # Get TheHive case.
            thehive_case_response = self.thehive_client.get_case(self.thehive_case_id)
            thehive_case = thehive_case_response.json()

            update_event = self.use_misp_event(thehive_case)
            if update_event:
                self.misp_event = self.misp_client.get_event(self.misp_event_id, pythonify=True)
            else:
                # Create an empty MISP Event.
                self.misp_event = MISPEvent()

            self.create_new_misp_event(thehive_case, update=update_event, distribution="0")

            # Add Tags if not in MISP Event
            if not self.misp_event.get("Tag"):
                self.misp_event["Tag"] = []

            # Get TheHive Case PAP.
            self.add_pap_tag(thehive_case)

            # Get TheHive Case TLP.
            self.add_tlp_tag(thehive_case)

            # Add Case Tags
            self.add_hive_case_tags_to_misp_event(thehive_case)

            # Get TheHive case observables.
            observables = self.thehive_client.get_case_observables(self.thehive_case_id)

            # Add Attribute to MISP Event if it doesn't exist.
            if not self.misp_event.get("Attribute"):
                self.misp_event["Attribute"] = []

            new_attributes = []

            # Iterate through each observable
            for observable in observables.json():
                # We only want to send observables marked as IOCs to MISP.
                if observable["ioc"]:
                    # Check if we're adding new attributes or updating existing ones.
                    if update_event:
                        # Returns the MISP attribute UUID so we can p
                        attribute_uuid = self.return_attribute_uuid(attribute=observable)
                        if attribute_uuid:
                            self.update_attribute_hive_tags(observable, attribute_uuid)
                        else:
                            new_attributes.append(self.new_misp_attribute(observable))
                    else:
                        new_attributes.append(self.new_misp_attribute(observable))

            # Add new attributes
            self.misp_event = self.misp_client.get_event(self.misp_event_id, pythonify=True)
            for new_attribute in new_attributes:
                self.misp_event.attributes.append(new_attribute)

            self.misp_client.update_event(event=self.misp_event, event_id=self.misp_event_id)

            # Log the MISP Event
            root.info(self.misp_event)

            self.report({'message': "Submitted to MISP!"})
        except Exception as e:
            self.error(traceback.format_exc())
            self.error(e)

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag=f'MISP:{self.misp_event_id}')]


if __name__ == '__main__':
    MISP().run()
