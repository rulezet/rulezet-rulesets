rule rule_icebreaker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'icebreaker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icebreaker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_icebreaker_offensive_tool_keyword = /\sicebreaker\.py/ nocase ascii wide
                        $string2_icebreaker_offensive_tool_keyword = " -oA icebreaker-scan" nocase ascii wide
                        $string3_icebreaker_offensive_tool_keyword = " --password-list " nocase ascii wide
                        $string4_icebreaker_offensive_tool_keyword = /\s\-\-script\ssmb\-security\-mode.{0,100}smb\-enum\-shares\s/ nocase ascii wide
                        $string5_icebreaker_offensive_tool_keyword = /\ssmb\-cmds\.txt/ nocase ascii wide
                        $string6_icebreaker_offensive_tool_keyword = /\.py.{0,100}found\-users\.txt/ nocase ascii wide
                        $string7_icebreaker_offensive_tool_keyword = "/DanMcInerney/ridenum"
                        $string8_icebreaker_offensive_tool_keyword = /\/DeathStar\/DeathStar\.py/
                        $string9_icebreaker_offensive_tool_keyword = /\/icebreaker\.git/ nocase ascii wide
                        $string10_icebreaker_offensive_tool_keyword = /\/icebreaker\.py/ nocase ascii wide
                        $string11_icebreaker_offensive_tool_keyword = "/lgandx/Responder"
                        $string12_icebreaker_offensive_tool_keyword = "/opt/icebreaker"
                        $string13_icebreaker_offensive_tool_keyword = /\/Responder\/Responder\.conf/
                        $string14_icebreaker_offensive_tool_keyword = /\/ridenum\/ridenum\.py/
                        $string15_icebreaker_offensive_tool_keyword = /\/shares\-with\-SCF\.txt/
                        $string16_icebreaker_offensive_tool_keyword = /\/smb\-cmds\.txt/
                        $string17_icebreaker_offensive_tool_keyword = /\/smb\-signing\-disabled\-hosts\.txt/
                        $string18_icebreaker_offensive_tool_keyword = /\/theHarvester\.py/
                        $string19_icebreaker_offensive_tool_keyword = "/virtualenvs/icebreaker"
                        $string20_icebreaker_offensive_tool_keyword = /\\icebreaker\.py/ nocase ascii wide
                        $string21_icebreaker_offensive_tool_keyword = /1mil\-AD\-passwords\.txt/ nocase ascii wide
                        $string22_icebreaker_offensive_tool_keyword = "byt3bl33d3r/DeathStar" nocase ascii wide
                        $string23_icebreaker_offensive_tool_keyword = "CoreSecurity/impacket/" nocase ascii wide
                        $string24_icebreaker_offensive_tool_keyword = "DanMcInerney/Empire" nocase ascii wide
                        $string25_icebreaker_offensive_tool_keyword = "DanMcInerney/icebreaker" nocase ascii wide
                        $string26_icebreaker_offensive_tool_keyword = "DanMcInerney/theHarvester" nocase ascii wide
                        $string27_icebreaker_offensive_tool_keyword = /found\-passwords\.txt/ nocase ascii wide
                        $string28_icebreaker_offensive_tool_keyword = /https\:\/\/0\.0\.0\.0\:1337/ nocase ascii wide
                        $string29_icebreaker_offensive_tool_keyword = "icebreaker:P@ssword123456" nocase ascii wide
                        $string30_icebreaker_offensive_tool_keyword = /icebreaker\-master\.zip/ nocase ascii wide
                        $string31_icebreaker_offensive_tool_keyword = /icebreaker\-scan\.xml/ nocase ascii wide
                        $string32_icebreaker_offensive_tool_keyword = "Invoke-Cats -pwds" nocase ascii wide
                        $string33_icebreaker_offensive_tool_keyword = /Invoke\-Cats\.ps1/ nocase ascii wide
                        $string34_icebreaker_offensive_tool_keyword = /Invoke\-Pwds\.ps1/ nocase ascii wide
                        $string35_icebreaker_offensive_tool_keyword = /logs\/Responder\-Session\.log/ nocase ascii wide
                        $string36_icebreaker_offensive_tool_keyword = /logs\/ridenum\.log/ nocase ascii wide
                        $string37_icebreaker_offensive_tool_keyword = /logs\/shares\-with\-SCF\.txt/ nocase ascii wide
                        $string38_icebreaker_offensive_tool_keyword = /logs\/theHarvester\.py\.log/ nocase ascii wide
                        $string39_icebreaker_offensive_tool_keyword = "net localgroup administrators icebreaker" nocase ascii wide
                        $string40_icebreaker_offensive_tool_keyword = "net user /add icebreaker " nocase ascii wide
                        $string41_icebreaker_offensive_tool_keyword = /ntlmrelayx\.py\.log/ nocase ascii wide
                        $string42_icebreaker_offensive_tool_keyword = "sudo tmux new -s icebreaker"
                        $string43_icebreaker_offensive_tool_keyword = /\-\-wordlist\=.{0,100}\-passwords\.txt/ nocase ascii wide
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