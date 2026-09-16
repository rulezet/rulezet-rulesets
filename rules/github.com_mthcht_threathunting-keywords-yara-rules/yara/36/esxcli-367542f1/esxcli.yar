rule esxcli
{
    meta:
        description = "Detection patterns for the tool 'esxcli' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "esxcli"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "esxcli network firewall set -enabled f" nocase ascii wide
                        $string2 = "esxcli network firewall set --enabled f" nocase ascii wide
                        $string3 = "esxcli system account add" nocase ascii wide
                        $string4 = "esxcli system account remove" nocase ascii wide
                        $string5 = /esxcli\ssystem\saccount\sset\s\-i\s.{0,1000}\s\-s\st/ nocase ascii wide
                        $string6 = "esxcli system auditrecords local disable" nocase ascii wide
                        $string7 = "esxcli system coredump file set --unconfigure" nocase ascii wide
                        $string8 = "esxcli system permission list" nocase ascii wide
                        $string9 = "esxcli system settings encryption set - require-exec-installed-only=F" nocase ascii wide
                        $string10 = "esxcli system settings encryption set - require-secure-boot=F" nocase ascii wide
                        $string11 = "esxcli system settings kernel set -s execInstalledOnly -v F" nocase ascii wide
                        $string12 = "esxcli system syslog config set --logdir=/tmp" nocase ascii wide
                        $string13 = "esxcli vm process kill " nocase ascii wide
                        $string14 = "esxcli vm process list" nocase ascii wide

    condition:
        any of them
}