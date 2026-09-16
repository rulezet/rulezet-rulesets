rule rule_netkit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'netkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_netkit_offensive_tool_keyword = /\/netkit\.git/ nocase ascii wide
                        $string2_netkit_offensive_tool_keyword = /\/netkit\/client\/shell\.py/ nocase ascii wide
                        $string3_netkit_offensive_tool_keyword = /\/netkit\/src\/netkit\./ nocase ascii wide
                        $string4_netkit_offensive_tool_keyword = /\[\+\]\ssuccessfully\sself\sdestructed\sserver/ nocase ascii wide
                        $string5_netkit_offensive_tool_keyword = /\\netkit\\client\\shell\.py/ nocase ascii wide
                        $string6_netkit_offensive_tool_keyword = /\\netkit\\src\\netkit\./ nocase ascii wide
                        $string7_netkit_offensive_tool_keyword = "8dece0ec5b60725419e384b317c5be3c15d3cc12c1c7da28a53ec344118f9cd9" nocase ascii wide
                        $string8_netkit_offensive_tool_keyword = "CONFIG_NETKIT_DEBUG" nocase ascii wide
                        $string9_netkit_offensive_tool_keyword = /ls\s\-la\snetkit\.ko/ nocase ascii wide
                        $string10_netkit_offensive_tool_keyword = /NETKIT_LOG\(\\"/ nocase ascii wide
                        $string11_netkit_offensive_tool_keyword = /NETKIT_XOR\\x00/ nocase ascii wide
                        $string12_netkit_offensive_tool_keyword = "Notselwyn/netkit" nocase ascii wide
                        $string13_netkit_offensive_tool_keyword = /run_kmod\.sh\snetkit\.ko\snetkit/
                        $string14_netkit_offensive_tool_keyword = /run_python\.sh\sclient\/shell\.py/

    condition:
        any of them
}