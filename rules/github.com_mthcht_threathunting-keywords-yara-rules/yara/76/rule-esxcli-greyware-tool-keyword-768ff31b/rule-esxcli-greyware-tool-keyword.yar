rule rule_esxcli_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'esxcli' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "esxcli"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_esxcli_greyware_tool_keyword = "esxcli network firewall set -enabled f" nocase ascii wide
                        $string2_esxcli_greyware_tool_keyword = "esxcli network firewall set --enabled f" nocase ascii wide
                        $string3_esxcli_greyware_tool_keyword = "esxcli system account add" nocase ascii wide
                        $string4_esxcli_greyware_tool_keyword = "esxcli system account remove" nocase ascii wide
                        $string5_esxcli_greyware_tool_keyword = /esxcli\ssystem\saccount\sset\s\-i\s.{0,1000}\s\-s\st/ nocase ascii wide
                        $string6_esxcli_greyware_tool_keyword = "esxcli system auditrecords local disable" nocase ascii wide
                        $string7_esxcli_greyware_tool_keyword = "esxcli system coredump file set --unconfigure" nocase ascii wide
                        $string8_esxcli_greyware_tool_keyword = "esxcli system permission list" nocase ascii wide
                        $string9_esxcli_greyware_tool_keyword = "esxcli system settings encryption set - require-exec-installed-only=F" nocase ascii wide
                        $string10_esxcli_greyware_tool_keyword = "esxcli system settings encryption set - require-secure-boot=F" nocase ascii wide
                        $string11_esxcli_greyware_tool_keyword = "esxcli system settings kernel set -s execInstalledOnly -v F" nocase ascii wide
                        $string12_esxcli_greyware_tool_keyword = "esxcli system syslog config set --logdir=/tmp" nocase ascii wide
                        $string13_esxcli_greyware_tool_keyword = "esxcli vm process kill " nocase ascii wide
                        $string14_esxcli_greyware_tool_keyword = "esxcli vm process list" nocase ascii wide

    condition:
        any of them
}