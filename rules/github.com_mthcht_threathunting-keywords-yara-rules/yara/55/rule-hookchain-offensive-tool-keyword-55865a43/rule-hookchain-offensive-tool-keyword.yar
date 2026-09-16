rule rule_hookchain_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hookchain' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hookchain"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hookchain_offensive_tool_keyword = /\/hookchain_finder64\.exe/ nocase ascii wide
                        $string2_hookchain_offensive_tool_keyword = /\/HookChain_msg\.exe/ nocase ascii wide
                        $string3_hookchain_offensive_tool_keyword = /\[\+\]\sCreating\sHookChain\simplants/ nocase ascii wide
                        $string4_hookchain_offensive_tool_keyword = /\[\+\]\sCreating\sHookChain\simplants/ nocase ascii wide
                        $string5_hookchain_offensive_tool_keyword = /\[\+\]\sHookChain\simplanted\!\s\\\\o\// nocase ascii wide
                        $string6_hookchain_offensive_tool_keyword = /\[\+\]\sHookChain\simplanted\!/ nocase ascii wide
                        $string7_hookchain_offensive_tool_keyword = /\[\+\]\sListing\sntdll\sNt\/Zw\sfunctions/ nocase ascii wide
                        $string8_hookchain_offensive_tool_keyword = /\\HookChain\.vcxproj/ nocase ascii wide
                        $string9_hookchain_offensive_tool_keyword = /\\hookchain_finder64\.c/ nocase ascii wide
                        $string10_hookchain_offensive_tool_keyword = /\\hookchain_finder64\.exe/ nocase ascii wide
                        $string11_hookchain_offensive_tool_keyword = /\\HookChain_msg\.exe/ nocase ascii wide
                        $string12_hookchain_offensive_tool_keyword = /\\HookChain_msg\.sln/ nocase ascii wide
                        $string13_hookchain_offensive_tool_keyword = /\]\sInjecting\sremote\sshellcode/ nocase ascii wide
                        $string14_hookchain_offensive_tool_keyword = "461df8ad66af0d6635bc8e389f307569c01f1b589319b8a887578b221c943b03" nocase ascii wide
                        $string15_hookchain_offensive_tool_keyword = /72e0ca8ac2312f9bda3badfc199df5bd0a224dcbdfa681a6fda0e3f5a774f7b6\s\?\s\?/ nocase ascii wide
                        $string16_hookchain_offensive_tool_keyword = "a43682fd04ffe7d7a41a4b9a1afeddda45f2a74cca6632bbf4d7d6c110e2ff80" nocase ascii wide
                        $string17_hookchain_offensive_tool_keyword = "B0C08C11-23C4-495F-B40B-14066F12FAAB" nocase ascii wide
                        $string18_hookchain_offensive_tool_keyword = "helviojunior/hookchain" nocase ascii wide
                        $string19_hookchain_offensive_tool_keyword = "HookChainFinder M4v3r1ck by Sec4US Team" nocase ascii wide
                        $string20_hookchain_offensive_tool_keyword = "Message Box created from HookChain" nocase ascii wide
                        $string21_hookchain_offensive_tool_keyword = "Process injected MessageBox" nocase ascii wide

    condition:
        any of them
}