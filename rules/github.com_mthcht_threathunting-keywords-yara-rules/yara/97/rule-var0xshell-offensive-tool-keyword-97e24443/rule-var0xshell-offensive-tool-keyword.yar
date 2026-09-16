rule rule_var0xshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'var0xshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "var0xshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_var0xshell_offensive_tool_keyword = /\sObfuscated\-Code\.py/ nocase ascii wide
                        $string2_var0xshell_offensive_tool_keyword = "#Author Yehia Elghaly" nocase ascii wide
                        $string3_var0xshell_offensive_tool_keyword = /\#Bind\sShell\s\(Client\)\s\(XOR\sAlgorithm\)/ nocase ascii wide
                        $string4_var0xshell_offensive_tool_keyword = /\/Obfuscated\-Code\.py/ nocase ascii wide
                        $string5_var0xshell_offensive_tool_keyword = /\/var0xshell\.git/
                        $string6_var0xshell_offensive_tool_keyword = /\\Obfuscated\-Code\.py/ nocase ascii wide
                        $string7_var0xshell_offensive_tool_keyword = "b80bb505227429df0b61a07d2ab57c02a48043fbd90d4680192b1698e9a2f37a" nocase ascii wide
                        $string8_var0xshell_offensive_tool_keyword = "e376445d4c432d5f3c61e4584974941028c2975b97ee1461e4f00c65eb09a0ed" nocase ascii wide
                        $string9_var0xshell_offensive_tool_keyword = "e379046040e17b60f1311e1d406a5bd9e34fd3f8b9e22cbceed612a6c3a689a9" nocase ascii wide
                        $string10_var0xshell_offensive_tool_keyword = "yehia-mamdouh/var0xshell" nocase ascii wide

    condition:
        any of them
}