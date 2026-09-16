rule Ninja
{
    meta:
        description = "Detection patterns for the tool 'Ninja' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ninja"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sNinja\.py/ nocase ascii wide
                        $string2 = /\sstart_campaign\.py/ nocase ascii wide
                        $string3 = /\.\/Ninja\.py/
                        $string4 = "/ahmedkhlief/Ninja/" nocase ascii wide
                        $string5 = /\/ninja\.crt/ nocase ascii wide
                        $string6 = /\/Ninja\.git/ nocase ascii wide
                        $string7 = /\/ninja\.key/ nocase ascii wide
                        $string8 = /\/Ninja\.py/ nocase ascii wide
                        $string9 = "/opt/Ninja/" nocase ascii wide
                        $string10 = /\/payload2\.ps1/ nocase ascii wide
                        $string11 = /\/start_campaign\.py/ nocase ascii wide
                        $string12 = /\/webshell\.py/ nocase ascii wide
                        $string13 = /\\Ninja\.py/ nocase ascii wide
                        $string14 = /\\start_campaign\.py/ nocase ascii wide
                        $string15 = "agents/Follina-2" nocase ascii wide
                        $string16 = "ahmedkhlief/Ninja" nocase ascii wide
                        $string17 = /AMSI_Bypass\.ps1/ nocase ascii wide
                        $string18 = /ASBBypass\.ps1/ nocase ascii wide
                        $string19 = "b64stager" nocase ascii wide
                        $string20 = "'C2Default'" nocase ascii wide
                        $string21 = /c2\-logs\.txt/ nocase ascii wide
                        $string22 = /cmd_shellcodex64\./ nocase ascii wide
                        $string23 = /cmd_shellcodex86\./ nocase ascii wide
                        $string24 = /create\-aws\-instance\.py/ nocase ascii wide
                        $string25 = "donut-shellcode" nocase ascii wide
                        $string26 = /dropper_cs\.exe/ nocase ascii wide
                        $string27 = /Find\-PSServiceAccounts\.ps1/ nocase ascii wide
                        $string28 = /Follina\.Ninja/ nocase ascii wide
                        $string29 = /Follina\/follina\.html/ nocase ascii wide
                        $string30 = "Follina/Follinadoc" nocase ascii wide
                        $string31 = /get_beacon\(/ nocase ascii wide
                        $string32 = "Invoke-Kerberoast" nocase ascii wide
                        $string33 = /Invoke\-Kerberoast\.ps1/ nocase ascii wide
                        $string34 = "Invoke-Mimikatz-old" nocase ascii wide
                        $string35 = "Invoke-WMIExec" nocase ascii wide
                        $string36 = /Kerberoast\.py/ nocase ascii wide
                        $string37 = "Ninja c2" nocase ascii wide
                        $string38 = "ninjac2" nocase ascii wide
                        $string39 = /Obfuscate\.py/ nocase ascii wide
                        $string40 = "payloads/Follina" nocase ascii wide
                        $string41 = "payloads/Powershell" nocase ascii wide
                        $string42 = "payloads/shellcodes" nocase ascii wide
                        $string43 = /python3\sNinja\.py/ nocase ascii wide
                        $string44 = /python3\sstart_campaign\.py/ nocase ascii wide
                        $string45 = /safetydump\.ninja/ nocase ascii wide
                        $string46 = /safetydump\.ninja/ nocase ascii wide
                        $string47 = /SharpHound\.ps1/ nocase ascii wide
                        $string48 = /simple_dropper\.ninja/ nocase ascii wide
                        $string49 = "webshell_execute" nocase ascii wide

    condition:
        any of them
}