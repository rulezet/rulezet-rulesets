rule sshtunnel
{
    meta:
        description = "Detection patterns for the tool 'sshtunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshtunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " install -c conda-forge sshtunnel" nocase ascii wide
                        $string2 = " -m sshtunnel " nocase ascii wide
                        $string3 = /\ssshtunnel\.py/ nocase ascii wide
                        $string4 = /\sSSHTunnelForwarder\(/ nocase ascii wide
                        $string5 = "/sshtunnel -"
                        $string6 = /\/sshtunnel\.git/ nocase ascii wide
                        $string7 = /\/sshtunnel\.py/ nocase ascii wide
                        $string8 = "/sshtunnel/tarball/" nocase ascii wide
                        $string9 = "/sshtunnel/zipball/" nocase ascii wide
                        $string10 = /\\sshtunnel\.py/ nocase ascii wide
                        $string11 = "c89b4490de04897b1c16e5dae1c10ef10e60c56294bd4ca45d1669f5dcb6f9e3" nocase ascii wide
                        $string12 = /Creating\sSSHTunnelForwarder.{0,1000}paramiko/ nocase ascii wide
                        $string13 = "easy_install sshtunnel" nocase ascii wide
                        $string14 = "from sshtunnel import " nocase ascii wide
                        $string15 = "from sshtunnel import SSHTunnelForwarder" nocase ascii wide
                        $string16 = "import sshtunnel" nocase ascii wide
                        $string17 = "pahaz/sshtunnel" nocase ascii wide
                        $string18 = "pip install sshtunnel" nocase ascii wide
                        $string19 = /sshtunnel\.readthedocs\.io/ nocase ascii wide
                        $string20 = /sshtunnel\.readthedocs\.org/ nocase ascii wide

    condition:
        any of them
}