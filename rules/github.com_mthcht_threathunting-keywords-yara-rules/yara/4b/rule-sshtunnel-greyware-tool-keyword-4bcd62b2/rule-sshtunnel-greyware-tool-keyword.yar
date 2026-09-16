rule rule_sshtunnel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshtunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshtunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_sshtunnel_greyware_tool_keyword = " install -c conda-forge sshtunnel" nocase ascii wide
                        $string2_sshtunnel_greyware_tool_keyword = " -m sshtunnel " nocase ascii wide
                        $string3_sshtunnel_greyware_tool_keyword = /\ssshtunnel\.py/ nocase ascii wide
                        $string4_sshtunnel_greyware_tool_keyword = /\sSSHTunnelForwarder\(/ nocase ascii wide
                        $string5_sshtunnel_greyware_tool_keyword = "/sshtunnel -"
                        $string6_sshtunnel_greyware_tool_keyword = /\/sshtunnel\.git/ nocase ascii wide
                        $string7_sshtunnel_greyware_tool_keyword = /\/sshtunnel\.py/ nocase ascii wide
                        $string8_sshtunnel_greyware_tool_keyword = "/sshtunnel/tarball/" nocase ascii wide
                        $string9_sshtunnel_greyware_tool_keyword = "/sshtunnel/zipball/" nocase ascii wide
                        $string10_sshtunnel_greyware_tool_keyword = /\\sshtunnel\.py/ nocase ascii wide
                        $string11_sshtunnel_greyware_tool_keyword = "c89b4490de04897b1c16e5dae1c10ef10e60c56294bd4ca45d1669f5dcb6f9e3" nocase ascii wide
                        $string12_sshtunnel_greyware_tool_keyword = /Creating\sSSHTunnelForwarder.{0,1000}paramiko/ nocase ascii wide
                        $string13_sshtunnel_greyware_tool_keyword = "easy_install sshtunnel" nocase ascii wide
                        $string14_sshtunnel_greyware_tool_keyword = "from sshtunnel import " nocase ascii wide
                        $string15_sshtunnel_greyware_tool_keyword = "from sshtunnel import SSHTunnelForwarder" nocase ascii wide
                        $string16_sshtunnel_greyware_tool_keyword = "import sshtunnel" nocase ascii wide
                        $string17_sshtunnel_greyware_tool_keyword = "pahaz/sshtunnel" nocase ascii wide
                        $string18_sshtunnel_greyware_tool_keyword = "pip install sshtunnel" nocase ascii wide
                        $string19_sshtunnel_greyware_tool_keyword = /sshtunnel\.readthedocs\.io/ nocase ascii wide
                        $string20_sshtunnel_greyware_tool_keyword = /sshtunnel\.readthedocs\.org/ nocase ascii wide

    condition:
        any of them
}