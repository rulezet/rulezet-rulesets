rule rule_Invoke_Stealth_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Stealth' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Stealth"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_Stealth_offensive_tool_keyword = /\s\[\+\]\sSUCCESS\:\sAMSI\sBypassed\!/ nocase ascii wide
                        $string2_Invoke_Stealth_offensive_tool_keyword = " by @JoelGMSec " nocase ascii wide
                        $string3_Invoke_Stealth_offensive_tool_keyword = /\sInvoke\-Stealth\.ps1/ nocase ascii wide
                        $string4_Invoke_Stealth_offensive_tool_keyword = /\srevshell\.ps1/ nocase ascii wide
                        $string5_Invoke_Stealth_offensive_tool_keyword = /\\"iN\\"\+\\"voK\\"\+\\"e\\"\+\\"\-\\"\+\\"eXP\\"\+\\"re\\"\+\\"sSi\\"\+\\"oN\\"/ nocase ascii wide
                        $string6_Invoke_Stealth_offensive_tool_keyword = /\.ps1\s\-technique\sBetterXencrypt/ nocase ascii wide
                        $string7_Invoke_Stealth_offensive_tool_keyword = /\.ps1\s\-technique\sChameleon/ nocase ascii wide
                        $string8_Invoke_Stealth_offensive_tool_keyword = /\.ps1\s\-technique\sPSObfuscation/ nocase ascii wide
                        $string9_Invoke_Stealth_offensive_tool_keyword = /\.ps1\s\-technique\sPyFuscation/ nocase ascii wide
                        $string10_Invoke_Stealth_offensive_tool_keyword = /\.ps1\s\-technique\sReverseB64/ nocase ascii wide
                        $string11_Invoke_Stealth_offensive_tool_keyword = /\/Invoke\-Stealth\.git/ nocase ascii wide
                        $string12_Invoke_Stealth_offensive_tool_keyword = /\/invoke\-stealth\.php/ nocase ascii wide
                        $string13_Invoke_Stealth_offensive_tool_keyword = /\/Invoke\-Stealth\.ps1/ nocase ascii wide
                        $string14_Invoke_Stealth_offensive_tool_keyword = /\/printernightmare\.ps1/ nocase ascii wide
                        $string15_Invoke_Stealth_offensive_tool_keyword = /\/revshell\.ps1/ nocase ascii wide
                        $string16_Invoke_Stealth_offensive_tool_keyword = /\[\!\]\sAvoid\smixing\sBetterXencrypt\swith\sanother\stechniques/ nocase ascii wide
                        $string17_Invoke_Stealth_offensive_tool_keyword = /\[\#\]\sChecking\sfile\sagainst\sAMSI\sTrigger/ nocase ascii wide
                        $string18_Invoke_Stealth_offensive_tool_keyword = /\[\+\]\sEncoding\swith\sbase64\sand\sreverse\sit\sto\savoid\sdetections/ nocase ascii wide
                        $string19_Invoke_Stealth_offensive_tool_keyword = /\[\+\]\sLoading\sBetterXencrypt\sand\sdoing\ssome\sencryption\swith\srandom\siterations/ nocase ascii wide
                        $string20_Invoke_Stealth_offensive_tool_keyword = /\[\+\]\sLoading\sPSObfuscation\sand\srandomizing\sscript/ nocase ascii wide
                        $string21_Invoke_Stealth_offensive_tool_keyword = /\[\+\]\sLoading\sPyFuscation\sand\sdoing\s\$some\sobfuscation/ nocase ascii wide
                        $string22_Invoke_Stealth_offensive_tool_keyword = /\\AmsiTrigger\.pdb/ nocase ascii wide
                        $string23_Invoke_Stealth_offensive_tool_keyword = /\\Invoke\-Stealth\.ps1/ nocase ascii wide
                        $string24_Invoke_Stealth_offensive_tool_keyword = /\\printernightmare\.ps1/ nocase ascii wide
                        $string25_Invoke_Stealth_offensive_tool_keyword = /\\revshell\.ps1/ nocase ascii wide
                        $string26_Invoke_Stealth_offensive_tool_keyword = /\]\sWriting\sobfuscated\spayload\sto\s/ nocase ascii wide
                        $string27_Invoke_Stealth_offensive_tool_keyword = "==gCkV2Zh5WYNNXZB5SeoBXYyd2b0BXeyNkL5RXayV3YlNlLtVGdzl3U" nocase ascii wide
                        $string28_Invoke_Stealth_offensive_tool_keyword = "==gNyEDMx80UJpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W" nocase ascii wide
                        $string29_Invoke_Stealth_offensive_tool_keyword = "==gQDVkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W" nocase ascii wide
                        $string30_Invoke_Stealth_offensive_tool_keyword = "==wcvJXZapjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W" nocase ascii wide
                        $string31_Invoke_Stealth_offensive_tool_keyword = "==wMykDWJNlTBpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W" nocase ascii wide
                        $string32_Invoke_Stealth_offensive_tool_keyword = "==wNTN0SQpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W" nocase ascii wide
                        $string33_Invoke_Stealth_offensive_tool_keyword = "==wQCNkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W" nocase ascii wide
                        $string34_Invoke_Stealth_offensive_tool_keyword = "2ba17d622736a4d3132c17db3b8c725f001fdbe7fca4b9b4248262b5e54a4107" nocase ascii wide
                        $string35_Invoke_Stealth_offensive_tool_keyword = "729ed6976b1710e57fb5e486e1a017b39a437895ae86056c2aa3d45763a6f330" nocase ascii wide
                        $string36_Invoke_Stealth_offensive_tool_keyword = "7aa6a3be25f05eb6a5c5cda7f10e48007dae601c9918a9734db3697ed6c63afc" nocase ascii wide
                        $string37_Invoke_Stealth_offensive_tool_keyword = "7becedb670137807e079f535c7bec03131414f90e8e2a70e4c989b9d9167f4aa" nocase ascii wide
                        $string38_Invoke_Stealth_offensive_tool_keyword = "9eb21ba1323fac7c64c1e03fb3c29e374ab7d99ab9c4d27eb4c3166575769a0f" nocase ascii wide
                        $string39_Invoke_Stealth_offensive_tool_keyword = "aec7b9f5d2bf5b9ae363fce9c7426bf03a08271f1f7ea1bba4bc5e05f717ac69" nocase ascii wide
                        $string40_Invoke_Stealth_offensive_tool_keyword = /AMSITrigger\.exe/ nocase ascii wide
                        $string41_Invoke_Stealth_offensive_tool_keyword = /BetterXencrypt\.ps1/ nocase ascii wide
                        $string42_Invoke_Stealth_offensive_tool_keyword = "c288394f0c71cea2f14223899de957ca2a5d101bcbfe1efacc23e480fabde335" nocase ascii wide
                        $string43_Invoke_Stealth_offensive_tool_keyword = "Invoke-BetterXencrypt" nocase ascii wide
                        $string44_Invoke_Stealth_offensive_tool_keyword = "Invoke-PSObfuscation" nocase ascii wide
                        $string45_Invoke_Stealth_offensive_tool_keyword = "JoelGMSec/Invoke-Stealth" nocase ascii wide
                        $string46_Invoke_Stealth_offensive_tool_keyword = /Load\-BetterXencrypt.{0,100}\s/ nocase ascii wide
                        $string47_Invoke_Stealth_offensive_tool_keyword = "Load-PSObfuscation" nocase ascii wide
                        $string48_Invoke_Stealth_offensive_tool_keyword = "Load-PyFuscation" nocase ascii wide
                        $string49_Invoke_Stealth_offensive_tool_keyword = /o\-printernightmare\.ps1/ nocase ascii wide
                        $string50_Invoke_Stealth_offensive_tool_keyword = "U3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5BZXNNYW5hZ2VkCg==" nocase ascii wide
                        $string51_Invoke_Stealth_offensive_tool_keyword = "W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQ2lwaGVyTW9kZV06OkNCQw==" nocase ascii wide
                        $string52_Invoke_Stealth_offensive_tool_keyword = "W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQ2lwaGVyTW9kZV06OkVDQg==" nocase ascii wide
                        $string53_Invoke_Stealth_offensive_tool_keyword = "W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpaZXJvcw==" nocase ascii wide
                        $string54_Invoke_Stealth_offensive_tool_keyword = "W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpBTlNJWDkyMw==" nocase ascii wide
                        $string55_Invoke_Stealth_offensive_tool_keyword = "W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpJU08xMDEyNg==" nocase ascii wide
                        $string56_Invoke_Stealth_offensive_tool_keyword = "W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpQS0NTNw==" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}