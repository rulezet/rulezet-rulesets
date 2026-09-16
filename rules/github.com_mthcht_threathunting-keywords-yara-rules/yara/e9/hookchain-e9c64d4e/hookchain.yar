rule hookchain
{
    meta:
        description = "Detection patterns for the tool 'hookchain' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hookchain"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/hookchain_finder64\.exe/ nocase ascii wide
                        $string2 = /\/HookChain_msg\.exe/ nocase ascii wide
                        $string3 = /\[\+\]\sCreating\sHookChain\simplants/ nocase ascii wide
                        $string4 = /\[\+\]\sCreating\sHookChain\simplants/ nocase ascii wide
                        $string5 = /\[\+\]\sHookChain\simplanted\!\s\\\\o\// nocase ascii wide
                        $string6 = /\[\+\]\sHookChain\simplanted\!/ nocase ascii wide
                        $string7 = /\[\+\]\sListing\sntdll\sNt\/Zw\sfunctions/ nocase ascii wide
                        $string8 = /\\HookChain\.vcxproj/ nocase ascii wide
                        $string9 = /\\hookchain_finder64\.c/ nocase ascii wide
                        $string10 = /\\hookchain_finder64\.exe/ nocase ascii wide
                        $string11 = /\\HookChain_msg\.exe/ nocase ascii wide
                        $string12 = /\\HookChain_msg\.sln/ nocase ascii wide
                        $string13 = /\]\sInjecting\sremote\sshellcode/ nocase ascii wide
                        $string14 = "461df8ad66af0d6635bc8e389f307569c01f1b589319b8a887578b221c943b03" nocase ascii wide
                        $string15 = /72e0ca8ac2312f9bda3badfc199df5bd0a224dcbdfa681a6fda0e3f5a774f7b6\s\?\s\?/ nocase ascii wide
                        $string16 = "a43682fd04ffe7d7a41a4b9a1afeddda45f2a74cca6632bbf4d7d6c110e2ff80" nocase ascii wide
                        $string17 = "B0C08C11-23C4-495F-B40B-14066F12FAAB" nocase ascii wide
                        $string18 = "helviojunior/hookchain" nocase ascii wide
                        $string19 = "HookChainFinder M4v3r1ck by Sec4US Team" nocase ascii wide
                        $string20 = "Message Box created from HookChain" nocase ascii wide
                        $string21 = "Process injected MessageBox" nocase ascii wide

    condition:
        any of them
}