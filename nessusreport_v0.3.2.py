#!/usr/bin/python

import sys
import getopt
import re
import cgi
import zipfile
from lxml import etree
from operator import itemgetter
from itertools import groupby


def parseNessusXML(xmlFile):
 
    events = ("start", "end")
    context = etree.iterparse(xmlFile, events=events)
    general_dict = {}
    attrib_dict = {}
    vulns = []
    target = "None"
    host_ip = "None"
    host_fqdn = "None"
    operating_system = "None"
    netbios_name = "None"
    mac_address = "None"
    plugin_id = 0
    cve_list = []
    osvdb_list = []
    xref_list = []
    bid_list = []

    for action, elem in context:
        if not elem.text:
            text = "None"
        else:
            text = elem.text
        
        if not elem.attrib:
            attrib_dict = {}
        else:    
            attrib_dict = elem.attrib
        
        general_dict[elem.tag] = text
        general_dict.update(attrib_dict)

        try:
            plugin_id = general_dict['pluginID']
        except:
            pass

        if elem.tag == "ReportHost" and action == "start": 
            general_dict['target'] = attrib_dict['name']
            target = attrib_dict['name']
            general_dict = {}
        
        if elem.tag == "ReportHost" and action == "end":
            target = "None"
            host_fqdn = "None"
            operating_system = "None"
            netbios_name = "None"
            mac_address = "None"
            plugin_id = 0
        
        if elem.tag == "tag" and action == "end":
            if attrib_dict['name'] == "host-fqdn":
                host_fqdn = text
            if attrib_dict['name'] == "operating-system":
                operating_system = text
            if attrib_dict['name'] == "netbios-name":
                netbios_name = text
            if attrib_dict['name'] == "host-ip":
                host_ip = text
            if attrib_dict['name'] == "mac-address":
                mac_address = text
        
        if elem.tag == "cve" and action == "end":
            cve_list.append(text)
        if elem.tag == "osvdb" and action == "end":
            osvdb_list.append(text)
        if elem.tag == "xref" and action == "end":
            xref_list.append(text)
        if elem.tag == "bid" and action == "end":
            bid_list.append(text)
        
        if elem.tag == "ReportItem" and action == "end":
            general_dict['target'] = target
            general_dict['host_ip'] = host_ip
            general_dict['host_fqdn'] = host_fqdn
            general_dict['operating_system'] = operating_system
            general_dict['mac_address'] = mac_address
            general_dict['netbios_name'] = netbios_name
            ref_str = ""
            for cve in cve_list:
                ref_str = ref_str + cve + ", "
            general_dict['cve'] = ref_str
            ref_str = ""
            for osvdb in osvdb_list:
                ref_str = ref_str + "OSVDB:" + osvdb + ", "
            general_dict['osvdb'] = ref_str
            ref_str = ""
            for bid in bid_list:
                ref_str = ref_str + "BID:" + bid + ", "
            general_dict['bid'] = ref_str
            ref_str = ""
            for xref in xref_list:
                ref_str = ref_str + xref + ", "
            general_dict['xref'] = ref_str

            vulns.append(general_dict)
            general_dict = {}
            cve_list = []
            osvdb_list = []
            xref_list = []
            bid_list = []
        
    return vulns


def strip_multiple_spaces(s):
    return re.sub('\s{2,}', ' ', s)


def generate_csv(vulns):
    #csv = "target|IP|host_fqdn|netbios_name|mac_address|operating_system|port|severity|risk_factor|plugin_name|pluginID|description|cvss_vector|cvss_base_score|av|ac|au|cvss_temporal_score|reference|exploit_available|pluginFamily|plugin_type|solution\n"
    #csv = "target|host_fqdn|netbios_name|mac_address|operating_system|port|severity|risk_factor|plugin_name|pluginID|description|cvss_vector|cvss_base_score|cvss3_vector|cvss3_base_score|av|pr|cvss_temporal_score|reference|exploit_available|pluginFamily|plugin_type|solution\n"
    #csv = "IP|Target|FQDN|Asset Name|Asset Operating System|Port|Severity|Mitigation Priority|Vulnerability Title|Description|CVSS Base Score|Attack Vector (AV)|CVSS Vector|Mitigation\n"
    csv = "IP|Target|FQDN|Asset Name|Asset Operating System|Port|Service|Severity|Mitigation Priority|Vulnerability Title|CVSS2 Base Score|Attack Vector (AV)|CVSS2 Vector|CVSS2 Temporal Score|CVSS2 Temporal Vector|CVSS3 Base Score|CVSS3 Vector|CVSS3 Temporal Score|CVSS3 Temporal Vector|Description|Mitigation|Output\n"

    for vuln in vulns:
        # fissi
        target = vuln['target']
        ip = vuln['host_ip']
        protocol = vuln['protocol'].upper()
        port = vuln['port']
        severity = vuln['severity']
        pluginID = vuln['pluginID']
        service_name = vuln['svc_name'].upper()

        # variabili
        try: plugin_name = vuln['pluginName']
        except: plugin_name = ""

        #add description, output and solution of vulnerability
        try:
            description = vuln['description']
            description = description.replace("\r"," ")
            description = description.replace("\n"," ")
        except: description = ""

        try:
            #plugin_output = cgi.escape(vuln['plugin_output'].strip()).replace("\n", " ").replace("\r", " ").replace("|", " ")
            plugin_output = vuln['plugin_output']
            plugin_output = plugin_output.replace("\r"," ")
            plugin_output = plugin_output.replace("\n"," ")
            plugin_output = plugin_output.replace("|"," ")
        except: plugin_output = "No output recorded"
        
        try:
            solution = vuln['solution']
            solution = solution.replace("\r","")
            solution = solution.replace("\n","")
        except: solution = ""

        try: risk_factor = vuln['risk_factor']
        except: risk_factor = ""
        try: plugin_publication_date = vuln['plugin_publication_date']
        except: plugin_publication_date = ""
        try: netbios_name = vuln['netbios_name']
        except: netbios_name = ""
        try: host_fqdn = vuln['host_fqdn']
        except: host_fqdn = ""
        try: operating_system = vuln['operating_system'].replace("\n", "/")
        except: operating_system = ""
        try: pluginFamily = vuln['pluginFamily'] 
        except: pluginFamily = ""
        try: plugin_type = vuln['plugin_type']
        except: plugin_type = ""
        try: exploit_available = vuln['exploit_available']
        except: exploit_available = ""
        try: cvss_base_score = vuln['cvss_base_score'].replace('.', ',')
        except: cvss_base_score = ""
        
        try:
            cvss_vector = vuln['cvss_vector'].split('#')[1]
            vulns_metrics = cvss_vector.split('/')
            av_dict = {'L':"Local", 'A':"Adjacent Network", 'N':"Network"}
            ac_dict = {'H':"High", 'M':"Medium", 'L':"Low"}
            au_dict = {'M':"Multiple", 'S':"Single", 'N':"None"}

            av = av_dict[vulns_metrics[0][3]]
            ac = ac_dict[vulns_metrics[1][3]]
            au = au_dict[vulns_metrics[2][3]]
        except:
            cvss_vector = ""
            av = ac = au = ""
        
        '''
        add CVSS 3.0
        '''
        
        try: cvss3_base_score = vuln['cvss3_base_score'].replace('.', ',')
        except: cvss3_base_score = ""
        try: cvss3_vector = vuln['cvss3_vector'][9:]
        except: cvss3_vector = ""

        
        '''Get Attack Vector and Privileges Required
        try:
            vulns_metrics = cvss3_vector.split('/')
            av3_dict = {'L':"Local", 'A':"Adjacent Network", 'N':"Network", 'P':"Physical"}
            ac3_dict = {'H':"High", 'L':"Low"}
            pr_dict = {'N':"None", 'L':"Low", 'H':"High"}
            ui_dict = {'R':"Required", 'N':"None"}
            av3 = av3_dict[vulns_metrics[3:]]
            pr = pr_dict[vuln_metric[3:]]
        except Exception as e:
            cvss3_vector = ""
            av3 = pr = ""'''

        try: cvss_temporal_score = vuln['cvss_temporal_score'].replace('.', ',')
        except: cvss_temporal_score = ""
        try: cvss_temporal_vector = vuln['cvss_temporal_vector'].split('#')[1]
        except: cvss_temporal_vector = ""
        try: cvss3_temporal_score = vuln['cvss3_temporal_score'].replace('.', ',')
        except: cvss3_temporal_score = ""
        try: cvss3_temporal_vector = vuln['cvss3_temporal_vector'][9:]
        except: cvss3_temporal_vector = ""
        try: cve = vuln['cve']
        except: cve = ""
        try: osvdb = vuln['osvdb']
        except: osvdb = ""
        try: xref = vuln['xref']
        except: xref = ""
        try: bid = vuln['bid']
        except: bid = ""
        try: mac_address = vuln['mac_address'].replace("\n", ",")
        except: mac_address = "None"

        reference = cve
        if bid != "":
            reference += bid
        if xref != "":
            reference += xref
        reference += "NSS-ID-" + pluginID
        
        '''
        Output with CVSS3 Score
        csv_line = target + "|" + host_fqdn + "|" + netbios_name + "|" + mac_address + "|" + operating_system + "|" + port + "/" + protocol + "|" + severity + "|" + risk_factor + "|" + plugin_name + "|" + pluginID + "|" + description + "|" + cvss_vector + "|" + cvss_base_score + "|" + cvss3_vector + "|" + cvss3_base_score + "|" + av + "|" + pr + "|" + cvss_temporal_score + "|" + reference + "|" + exploit_available + "|" + pluginFamily + "|" + plugin_type + "|" + solution + "\n"
        '''

        #csv_line = target + "|" + ip + "|" + host_fqdn + "|" + netbios_name + "|" + mac_address + "|" + operating_system + "|" + port + "/" + protocol + "|" + severity + "|" + risk_factor + "|" + plugin_name + "|" + pluginID + "|" + description + "|" + cvss_vector + "|" + cvss_base_score + "|" + av + "|" + ac + "|" + au + "|" + cvss_temporal_score + "|" + reference + "|" + exploit_available + "|" + pluginFamily + "|" + plugin_type + "|" + solution + "\n"

        #csv_line = ip + "|" + target + "|" + host_fqdn + "|" + netbios_name + "|" + operating_system + "|" + port + "/" + protocol + "|" + severity + "|" + risk_factor + "|" + plugin_name + "|" + description + "|" + cvss_base_score + "|" + av + "|" + cvss_vector + "|" + solution + "\n"

        csv_line = ip + "|" + target + "|" + host_fqdn + "|" + netbios_name + "|" + operating_system + "|" + port + "/" + protocol + "|" + service_name + "|" + severity + "|" + risk_factor + "|" + plugin_name + "|" + cvss_base_score + "|" + av + "|" + cvss_vector + "|" + cvss_temporal_score + "|" + cvss_temporal_vector + "|" + cvss3_base_score + "|" + cvss3_vector + "|" + cvss3_temporal_score + "|" + cvss3_temporal_vector + "|" + description + "|" + solution + "|" + plugin_output + "\n"

        csv += csv_line

    return csv


def generate_docx_by_vulns(document, vulns):

    carriage_description = '</w:t></w:r></w:p><w:p w:rsidR="00494473" w:rsidRDefault="00494473" w:rsidP="001504E9"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:ind w:left="136"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:color w:val="333333"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:lang w:val="en-US"/></w:rPr></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:color w:val="333333"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-GB"/></w:rPr><w:t>'
    carriage_target = '</w:t></w:r></w:p><w:p w:rsidR="00494473" w:rsidRPr="00494473" w:rsidRDefault="00494473" w:rsidP="00494473"><w:pPr><w:tabs><w:tab w:val="num" w:pos="980"/></w:tabs><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:ind w:left="360"/><w:jc w:val="center"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-US"/></w:rPr></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-US"/></w:rPr><w:t>'
    spacer = '<w:p w:rsidR="003D28D6" w:rsidRDefault="003D28D6"/>'
    vuln_table = '<w:tbl><w:tblPr><w:tblW w:w="15395" w:type="dxa"/><w:jc w:val="center"/><w:tblBorders><w:top w:val="single" w:sz="6" w:space="0" w:color="000000"/><w:left w:val="single" w:sz="6" w:space="0" w:color="000000"/><w:bottom w:val="single" w:sz="6" w:space="0" w:color="000000"/><w:right w:val="single" w:sz="6" w:space="0" w:color="000000"/><w:insideH w:val="single" w:sz="6" w:space="0" w:color="000000"/><w:insideV w:val="single" w:sz="6" w:space="0" w:color="000000"/></w:tblBorders><w:tblLayout w:type="fixed"/><w:tblCellMar><w:left w:w="0" w:type="dxa"/><w:right w:w="0" w:type="dxa"/></w:tblCellMar><w:tblLook w:val="0000" w:firstRow="0" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" w:noHBand="0" w:noVBand="0"/><w:tblCaption w:val="TABELLA VULNERABILITA"/></w:tblPr><w:tblGrid><w:gridCol w:w="2543"/><w:gridCol w:w="2406"/><w:gridCol w:w="2551"/><w:gridCol w:w="3969"/><w:gridCol w:w="3926"/></w:tblGrid><w:tr w:rsidR="00D60478" w:rsidRPr="00506469" w:rsidTr="007C6C80"><w:trPr><w:cantSplit/><w:trHeight w:val="146"/><w:jc w:val="center"/></w:trPr><w:tc><w:tcPr><w:tcW w:w="2543" w:type="dxa"/><w:shd w:val="solid" w:color="0161EF" w:fill="B8CCE4"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="00506469" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableHeading"/><w:rPr><w:color w:val="FFFFFF"/></w:rPr></w:pPr><w:r w:rsidRPr="00506469"><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>Servi</w:t></w:r><w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>ces</w:t></w:r></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="4957" w:type="dxa"/><w:gridSpan w:val="2"/><w:shd w:val="solid" w:color="0161EF" w:fill="B8CCE4"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="00506469" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableHeading"/><w:rPr><w:color w:val="FFFFFF"/></w:rPr></w:pPr><w:proofErr w:type="spellStart"/><w:r w:rsidRPr="00506469"><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>Vulnerabilit</w:t></w:r><w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>ies</w:t></w:r><w:proofErr w:type="spellEnd"/></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="3969" w:type="dxa"/><w:shd w:val="solid" w:color="0161EF" w:fill="B8CCE4"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="00506469" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableHeading"/><w:rPr><w:color w:val="FFFFFF"/></w:rPr></w:pPr><w:proofErr w:type="spellStart"/><w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>R</w:t></w:r><w:r w:rsidRPr="00506469"><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>emediation</w:t></w:r><w:proofErr w:type="spellEnd"/></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="3926" w:type="dxa"/><w:shd w:val="solid" w:color="0161EF" w:fill="B8CCE4"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="00506469" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableHeading"/><w:rPr><w:color w:val="FFFFFF"/></w:rPr></w:pPr><w:r w:rsidRPr="00506469"><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>Info</w:t></w:r></w:p></w:tc></w:tr><w:tr w:rsidR="00D60478" w:rsidRPr="00970807" w:rsidTr="007C6C80"><w:trPr><w:cantSplit/><w:trHeight w:val="1283"/><w:jc w:val="center"/></w:trPr><w:tc><w:tcPr><w:tcW w:w="2543" w:type="dxa"/><w:vMerge w:val="restart"/><w:shd w:val="solid" w:color="BFBFBF" w:fill="auto"/><w:vAlign w:val="center"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableContents"/><w:jc w:val="center"/><w:rPr><w:b/></w:rPr></w:pPr><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">VALUE22  </w:t></w:r></w:p><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableContents"/><w:jc w:val="center"/><w:rPr><w:b/></w:rPr></w:pPr><w:r><w:rPr><w:b/></w:rPr><w:t>(VALUE04/VALUE05)</w:t></w:r></w:p><w:p w:rsidR="00D60478" w:rsidRPr="0007399A" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableContents"/><w:jc w:val="center"/><w:rPr><w:b/></w:rPr></w:pPr></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="4957" w:type="dxa"/><w:gridSpan w:val="2"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:ind w:left="136"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:bCs/><w:color w:val="333333"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:lang w:val="en-GB"/></w:rPr></w:pPr></w:p><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:ind w:left="136"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:bCs/><w:color w:val="333333"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:lang w:val="en-GB"/></w:rPr></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:bCs/><w:color w:val="333333"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:lang w:val="en-GB"/></w:rPr><w:t>VALUE00</w:t></w:r></w:p><w:p w:rsidR="00D60478" w:rsidRPr="00970807" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:ind w:left="136"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:bCs/><w:color w:val="333333"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:lang w:val="en-GB"/></w:rPr></w:pPr></w:p><w:p w:rsidR="00494473" w:rsidRPr="00ED007C" w:rsidRDefault="00D60478" w:rsidP="00ED007C"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:ind w:left="136"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:color w:val="333333"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-GB"/></w:rPr></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:color w:val="333333"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-GB"/></w:rPr><w:t>VALUE14</w:t></w:r><w:r w:rsidRPr="00497E09"><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:color w:val="333333"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:lang w:val="en-GB"/></w:rPr><w:br/></w:r><w:r w:rsidRPr="00497E09"><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:color w:val="333333"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:lang w:val="en-GB"/></w:rPr><w:br/></w:r><w:r w:rsidRPr="00497E09"><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:bCs/><w:color w:val="333333"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:lang w:val="en-GB"/></w:rPr><w:t>Description:</w:t></w:r><w:r w:rsidRPr="00497E09"><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:color w:val="333333"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:lang w:val="en-GB"/></w:rPr><w:br/></w:r><w:r><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:color w:val="333333"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-GB"/></w:rPr><w:t>VALUE15</w:t></w:r></w:p><w:p w:rsidR="00D60478" w:rsidRPr="001735E8" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:rPr><w:lang w:val="en-US"/></w:rPr></w:pPr></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="3969" w:type="dxa"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableContents"/><w:ind w:left="80"/><w:rPr><w:color w:val="333333"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-GB"/></w:rPr></w:pPr></w:p><w:p w:rsidR="00D60478" w:rsidRPr="001735E8" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableContents"/><w:ind w:left="140"/><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman"/><w:b/><w:lang w:val="en-US"/></w:rPr></w:pPr><w:r><w:rPr><w:color w:val="333333"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-GB"/></w:rPr><w:t>VALUE16</w:t></w:r></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="3926" w:type="dxa"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="00AA130B" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableContents"/><w:rPr><w:color w:val="333333"/><w:sz w:val="18"/><w:szCs w:val="18"/><w:lang w:val="en-GB"/></w:rPr></w:pPr></w:p><w:p w:rsidR="00494473" w:rsidRPr="007C6C80" w:rsidRDefault="007C6C80" w:rsidP="00494473"><w:pPr><w:pStyle w:val="TableContents"/><w:ind w:left="140"/></w:pPr><w:r><w:t>VALUE17</w:t></w:r></w:p></w:tc></w:tr><w:tr w:rsidR="00D60478" w:rsidRPr="006F71DF" w:rsidTr="007C6C80"><w:trPr><w:cantSplit/><w:trHeight w:val="245"/><w:jc w:val="center"/></w:trPr><w:tc><w:tcPr><w:tcW w:w="2543" w:type="dxa"/><w:vMerge/><w:shd w:val="solid" w:color="BFBFBF" w:fill="auto"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="00970807" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableContents"/><w:rPr><w:rFonts w:ascii="Verdana" w:hAnsi="Verdana"/><w:lang w:eastAsia="it-IT"/></w:rPr></w:pPr></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="2406" w:type="dxa"/><w:shd w:val="clear" w:color="BFBFBF" w:fill="3366FF"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="00E42851" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableHeading"/><w:rPr><w:rFonts w:ascii="Verdana" w:hAnsi="Verdana"/><w:lang w:eastAsia="it-IT"/></w:rPr></w:pPr><w:proofErr w:type="spellStart"/><w:r w:rsidRPr="00E42851"><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>Severity</w:t></w:r><w:proofErr w:type="spellEnd"/></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="2551" w:type="dxa"/><w:shd w:val="clear" w:color="BFBFBF" w:fill="3366FF"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="00E626D3" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableHeading"/><w:rPr><w:color w:val="FFFFFF"/></w:rPr></w:pPr><w:r w:rsidRPr="00E626D3"><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>CVSSv2</w:t></w:r></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="3969" w:type="dxa"/><w:shd w:val="clear" w:color="BFBFBF" w:fill="3366FF"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="00E626D3" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableHeading"/><w:rPr><w:color w:val="FFFFFF"/></w:rPr></w:pPr><w:r w:rsidRPr="00E626D3"><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>IP target</w:t></w:r></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="3926" w:type="dxa"/><w:shd w:val="clear" w:color="BFBFBF" w:fill="3366FF"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="00E626D3" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableHeading"/><w:rPr><w:color w:val="FFFFFF"/></w:rPr></w:pPr><w:proofErr w:type="spellStart"/><w:r w:rsidRPr="00E626D3"><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>Skills</w:t></w:r><w:proofErr w:type="spellEnd"/></w:p></w:tc></w:tr><w:tr w:rsidR="00D60478" w:rsidRPr="006F71DF" w:rsidTr="007C6C80"><w:trPr><w:cantSplit/><w:jc w:val="center"/></w:trPr><w:tc><w:tcPr><w:tcW w:w="2543" w:type="dxa"/><w:vMerge/><w:shd w:val="solid" w:color="BFBFBF" w:fill="auto"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRPr="0071382A" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableContents"/><w:rPr><w:rFonts w:ascii="Verdana" w:hAnsi="Verdana"/><w:lang w:eastAsia="it-IT"/></w:rPr></w:pPr></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="2406" w:type="dxa"/><w:shd w:val="clear" w:color="BFBFBF" w:fill="auto"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:jc w:val="center"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-GB"/></w:rPr></w:pPr></w:p><w:p w:rsidR="00D60478" w:rsidRPr="001735E8" w:rsidRDefault="00D60478" w:rsidP="000A24CD"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:ind w:left="31"/><w:jc w:val="center"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-GB"/></w:rPr></w:pPr><w:bookmarkStart w:id="0" w:name="_GoBack"/><w:r w:rsidRPr="00B22CEE"><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="FF0000"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-GB"/></w:rPr><w:t>VALUE07</w:t></w:r><w:bookmarkEnd w:id="0"/></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="2551" w:type="dxa"/><w:shd w:val="clear" w:color="BFBFBF" w:fill="auto"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:jc w:val="center"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="20"/><w:szCs w:val="16"/><w:lang w:val="en-GB"/></w:rPr></w:pPr></w:p><w:p w:rsidR="00D60478" w:rsidRPr="00E626D3" w:rsidRDefault="00D60478" w:rsidP="000A24CD"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:ind w:hanging="13"/><w:jc w:val="center"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-GB"/></w:rPr></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-GB"/></w:rPr><w:t>VALUE02</w:t></w:r></w:p><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:pStyle w:val="TableContents"/><w:jc w:val="center"/><w:rPr><w:rFonts w:ascii="Verdana" w:hAnsi="Verdana"/><w:b/><w:lang w:eastAsia="it-IT"/></w:rPr></w:pPr></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="3969" w:type="dxa"/><w:shd w:val="clear" w:color="BFBFBF" w:fill="auto"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-GB"/></w:rPr></w:pPr></w:p><w:p w:rsidR="00494473" w:rsidRPr="00494473" w:rsidRDefault="00D60478" w:rsidP="000A24CD"><w:pPr><w:tabs><w:tab w:val="num" w:pos="-29"/></w:tabs><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:jc w:val="center"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-US"/></w:rPr></w:pPr><w:r w:rsidRPr="00494473"><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-US"/></w:rPr><w:t>VALUE18</w:t></w:r></w:p></w:tc><w:tc><w:tcPr><w:tcW w:w="3926" w:type="dxa"/><w:shd w:val="clear" w:color="BFBFBF" w:fill="auto"/></w:tcPr><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="001504E9"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:ind w:left="136"/><w:jc w:val="center"/><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-GB"/></w:rPr></w:pPr></w:p><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478" w:rsidP="000A24CD"><w:pPr><w:autoSpaceDE w:val="0"/><w:autoSpaceDN w:val="0"/><w:adjustRightInd w:val="0"/><w:jc w:val="center"/><w:rPr><w:rFonts w:ascii="Verdana" w:hAnsi="Verdana"/><w:b/></w:rPr></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Tahoma" w:hAnsi="Tahoma" w:cs="Tahoma"/><w:b/><w:color w:val="333333"/><w:sz w:val="16"/><w:szCs w:val="16"/><w:lang w:val="en-GB"/></w:rPr><w:t>VALUE09</w:t></w:r></w:p></w:tc></w:tr></w:tbl><w:br w:type="page" />'
    docx_header = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" mc:Ignorable="w14 wp14"><w:body><w:p w:rsidR="00136B2D" w:rsidRDefault="00136B2D"/><w:p w:rsidR="00D60478" w:rsidRDefault="00D60478"/>'
    docx_footer = '<w:sectPr w:rsidR="00ED007C" w:rsidSect="00D60478"><w:pgSz w:w="16838" w:h="11906" w:orient="landscape"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1417" w:header="708" w:footer="708" w:gutter="0"/><w:cols w:space="708"/><w:docGrid w:linePitch="360"/></w:sectPr></w:body></w:document>'

    critical_severity_color = "7030A0"
    high_severity_color = "FF0000"
    medium_severity_color = "FFC000"
    low_severity_color = "00B0F0"
    info_severity_color = "00B050"

    pluginID_lst = []

    for vuln in vulns:
        pluginID_lst.append(vuln['pluginID'])

    pluginID_lst = set(pluginID_lst)

    pluginID_target_dict = {}
    for pluginID in pluginID_lst:
        target_lst = []
        for vuln in vulns:
            if pluginID != vuln['pluginID']:
                continue
            target_lst.append(vuln['target'])
        target_lst = set(target_lst)
        pluginID_target_dict[pluginID] = target_lst


    docx = docx_header
    for i in range(1, 5):
        for pluginID in pluginID_lst:
        #idj=0
            for vuln in vulns:
                #fixed
                #print(idj)
                #idj= idj+1
                targets = ""
                protocol = vuln['protocol'].upper()
                port = vuln['port']
                severity = vuln['severity']
                description = "DESCRIPTION NOT FOUND!!!!!!"
                try:
                    description = strip_multiple_spaces(cgi.escape(vuln['description']).replace('\n\r\n','F1G4').replace('\n','').replace('F1G4','\n').replace('\n', carriage_description))
                except:
                    pass
                    #("error\n")
                svc_name = vuln['svc_name']

                #conditions
                if severity != str(5-i):
                    continue
                if vuln['pluginID'] != pluginID:
                    continue

                #replacements
                if severity == "0":
                    severity = "Info"
                    severity_color = info_severity_color
                elif severity == "1":
                    severity = "Low"
                    severity_color = low_severity_color
                elif severity == "2":
                    severity = "Medium"
                    severity_color = medium_severity_color
                elif severity == "3":
                    severity = "High"
                    severity_color = high_severity_color
                elif severity == "4":
                    severity = "High"
                    severity_color = high_severity_color
                for target in pluginID_target_dict[pluginID]:
                    targets += target + ", "
                
                targets = targets[:-2]

                #variable
                try: synopsis = cgi.escape(vuln['synopsis'])
                except: synopsis = "n/a"
                try: solution = cgi.escape(vuln['solution']).replace('\n', carriage_description)
                except: solution = "n/a"
                try: plugin_output = cgi.escape(vuln['plugin_output'].strip()).replace('\n', carriage_description)
                except: plugin_output = "n/a"
                try: plugin_name = cgi.escape(vuln['pluginName'])
                except: plugin_name = ""
                try: risk_factor = vuln['risk_factor']
                except: risk_factor = "n/a"
                try: plugin_publication_date = vuln['plugin_publication_date']
                except: plugin_publication_date = "n/a"
                try: netbios_name = vuln['netbios_name']
                except: netbios_name = "n/a"
                try: host_fqdn = vuln['host_fqdn']
                except: host_fqdn = "n/a"
                try: operating_system = vuln['operating_system'].replace('\n', " / ")
                except: operating_system = "n/a"
                try: pluginFamily = vuln['pluginFamily'] 
                except: pluginFamily = "n/a"
                try: plugin_type = vuln['plugin_type']
                except: plugin_type = "n/a"
                try: exploit_available = vuln['exploit_available']
                except: exploit_available = "n/a"
                try: cvss_base_score = vuln['cvss_base_score'].replace('.', ',')
                except: cvss_base_score = "n/a"
                try:
                    cvss_vector = vuln['cvss_vector'].split('#')[1]
                    skill_factor = cvss_vector.split('/')[1].split(':')[1]
                    if skill_factor == "L":
                        skill_factor = "Low"
                    elif skill_factor == "M":
                        skill_factor = "Medium"
                    elif skill_factor == "H":
                        skill_factor = "High"
                    else:
                        skill_factor = "n/a"
                except:
                    cvss_vector = "n/a"
                    skill_factor = "n/a"
                try: cvss_temporal_score = vuln['cvss_temporal_score'].replace('.', ',')
                except: cvss_temporal_score = "n/a"
                try: cve = vuln['cve']
                except: cve = ""
                try: osvdb = vuln['osvdb']
                except: osvdb = ""
                try: xref = vuln['xref']
                except: xref = ""
                try: bid = vuln['bid']
                except: bid = ""
                try: mac_address = vuln['mac_address']
                except: mac_address = "n/a"
        
                reference = cve
                if bid != "":
                    reference += bid
                if xref != "":
                    reference += xref
                reference += "NSS-ID-" + pluginID

                #init vuln table
                vuln_item = vuln_table
                severity_color_index = vuln_item[:vuln_item.find("VALUE07")].rfind('<w:color w:val="')
                vuln_item = vuln_item[:severity_color_index +16] + severity_color + '"/>' + vuln_item[severity_color_index +25:]
                
                #modifica vuln_table con parametri
                vuln_item = vuln_item.replace("VALUE00", plugin_name)
                vuln_item = vuln_item.replace("VALUE01", plugin_publication_date)
                vuln_item = vuln_item.replace("VALUE02", cvss_base_score)
                vuln_item = vuln_item.replace("VALUE03", cvss_temporal_score)
                vuln_item = vuln_item.replace("VALUE04", port)
                vuln_item = vuln_item.replace("VALUE05", protocol)
                vuln_item = vuln_item.replace("VALUE06", cvss_vector)
                vuln_item = vuln_item.replace("VALUE07", severity)
                vuln_item = vuln_item.replace("VALUE08", exploit_available)
                vuln_item = vuln_item.replace("VALUE09", skill_factor)
                vuln_item = vuln_item.replace("VALUE10", pluginID)
                vuln_item = vuln_item.replace("VALUE11", pluginFamily)
                vuln_item = vuln_item.replace("VALUE12", plugin_type)
                vuln_item = vuln_item.replace("VALUE13", reference)
                vuln_item = vuln_item.replace("VALUE14", synopsis)
                vuln_item = vuln_item.replace("VALUE15", description)
                vuln_item = vuln_item.replace("VALUE16", solution)
                vuln_item = vuln_item.replace("VALUE17", plugin_output)
                vuln_item = vuln_item.replace("VALUE18", targets)
                vuln_item = vuln_item.replace("VALUE19", host_fqdn)
                vuln_item = vuln_item.replace("VALUE20", mac_address)
                vuln_item = vuln_item.replace("VALUE21", operating_system)
                vuln_item = vuln_item.replace("VALUE22", svc_name)
        
                docx += vuln_item + spacer
                break

    docx += docx_footer
    return docx
        
        
def main(argv=None):
    if argv is None:
        argv = sys.argv
    if len(argv) < 4:
        print("Input Error!")
        return
    
    # read .nessus file
    vulns = []
    sessions = argv[1].split(",")
    for session in sessions:
        vulns.extend(parseNessusXML(session))
        vulns = list(map(itemgetter(0), groupby(sorted(vulns))))
    
    # read docx template file
    zin = zipfile.ZipFile(argv[2], 'r')

    # set mode
    outfile = argv[3]
    mode = 0
    try:
        if argv[4] == "1":
            mode = 1
        else:
            mode = 0
    except:
        pass

    # write docx report file
    zout = zipfile.ZipFile(outfile + ".docx", 'w')
    for item in zin.infolist():
        buffer = zin.read(item.filename)
        if (item.filename == 'word/document.xml'):
            if mode == 0:
                report = generate_docx_by_vulns(buffer, vulns)
#            else:
#                report = generate_docx_by_target(buffer, vulns)
            zout.writestr(item, report.encode("utf8"))
        else:
            zout.writestr(item, buffer)

    # write csv report file
    try:
        f = open(outfile + ".csv", "w")
        try:
            csv = generate_csv(vulns)
            f.write(csv.encode("utf8"))
        finally:
            f.close()
    except IOError:
        pass

    zout.close()
    zin.close()


if __name__ == "__main__":
    main()
