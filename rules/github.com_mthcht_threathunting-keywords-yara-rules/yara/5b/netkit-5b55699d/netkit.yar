rule netkit
{
    meta:
        description = "Detection patterns for the tool 'netkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/netkit\.git/ nocase ascii wide
                        $string2 = /\/netkit\/client\/shell\.py/ nocase ascii wide
                        $string3 = /\/netkit\/src\/netkit\./ nocase ascii wide
                        $string4 = /\[\+\]\ssuccessfully\sself\sdestructed\sserver/ nocase ascii wide
                        $string5 = /\\netkit\\client\\shell\.py/ nocase ascii wide
                        $string6 = /\\netkit\\src\\netkit\./ nocase ascii wide
                        $string7 = "8dece0ec5b60725419e384b317c5be3c15d3cc12c1c7da28a53ec344118f9cd9" nocase ascii wide
                        $string8 = "CONFIG_NETKIT_DEBUG" nocase ascii wide
                        $string9 = /ls\s\-la\snetkit\.ko/ nocase ascii wide
                        $string10 = /NETKIT_LOG\(\\"/ nocase ascii wide
                        $string11 = /NETKIT_XOR\\x00/ nocase ascii wide
                        $string12 = "Notselwyn/netkit" nocase ascii wide
                        $string13 = /run_kmod\.sh\snetkit\.ko\snetkit/
                        $string14 = /run_python\.sh\sclient\/shell\.py/

    condition:
        any of them
}