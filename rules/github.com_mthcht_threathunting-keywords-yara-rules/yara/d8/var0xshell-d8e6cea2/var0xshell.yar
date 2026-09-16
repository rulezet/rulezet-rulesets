rule var0xshell
{
    meta:
        description = "Detection patterns for the tool 'var0xshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "var0xshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sObfuscated\-Code\.py/ nocase ascii wide
                        $string2 = "#Author Yehia Elghaly" nocase ascii wide
                        $string3 = /\#Bind\sShell\s\(Client\)\s\(XOR\sAlgorithm\)/ nocase ascii wide
                        $string4 = /\/Obfuscated\-Code\.py/ nocase ascii wide
                        $string5 = /\/var0xshell\.git/
                        $string6 = /\\Obfuscated\-Code\.py/ nocase ascii wide
                        $string7 = "b80bb505227429df0b61a07d2ab57c02a48043fbd90d4680192b1698e9a2f37a" nocase ascii wide
                        $string8 = "e376445d4c432d5f3c61e4584974941028c2975b97ee1461e4f00c65eb09a0ed" nocase ascii wide
                        $string9 = "e379046040e17b60f1311e1d406a5bd9e34fd3f8b9e22cbceed612a6c3a689a9" nocase ascii wide
                        $string10 = "yehia-mamdouh/var0xshell" nocase ascii wide

    condition:
        any of them
}