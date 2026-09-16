rule rule_red_python_scripts_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'red-python-scripts' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "red-python-scripts"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_red_python_scripts_offensive_tool_keyword = /arp_mitm\.py/ nocase ascii wide
                        $string2_red_python_scripts_offensive_tool_keyword = /change\-windows10\-mac\-address\.py/ nocase ascii wide
                        $string3_red_python_scripts_offensive_tool_keyword = /lanscan_arp\.py/ nocase ascii wide
                        $string4_red_python_scripts_offensive_tool_keyword = /nmap_port_scanner\.py/ nocase ascii wide
                        $string5_red_python_scripts_offensive_tool_keyword = /nmap_port_scanner_ip_obj\.py/ nocase ascii wide
                        $string6_red_python_scripts_offensive_tool_keyword = /port_scanner_ip_obj\.py/ nocase ascii wide
                        $string7_red_python_scripts_offensive_tool_keyword = /port_scanner_regex\.py/ nocase ascii wide
                        $string8_red_python_scripts_offensive_tool_keyword = /wifi_dos_own\.py/ nocase ascii wide
                        $string9_red_python_scripts_offensive_tool_keyword = /wifi_dos3\.py/ nocase ascii wide
                        $string10_red_python_scripts_offensive_tool_keyword = /yeelight_discover\.py/ nocase ascii wide

    condition:
        any of them
}