rule icebreaker
{
    meta:
        description = "Detection patterns for the tool 'icebreaker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icebreaker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sicebreaker\.py/ nocase ascii wide
                        $string2 = " -oA icebreaker-scan" nocase ascii wide
                        $string3 = " --password-list " nocase ascii wide
                        $string4 = /\s\-\-script\ssmb\-security\-mode.{0,100}smb\-enum\-shares\s/ nocase ascii wide
                        $string5 = /\ssmb\-cmds\.txt/ nocase ascii wide
                        $string6 = /\.py.{0,100}found\-users\.txt/ nocase ascii wide
                        $string7 = "/DanMcInerney/ridenum"
                        $string8 = /\/DeathStar\/DeathStar\.py/
                        $string9 = /\/icebreaker\.git/ nocase ascii wide
                        $string10 = /\/icebreaker\.py/ nocase ascii wide
                        $string11 = "/lgandx/Responder"
                        $string12 = "/opt/icebreaker"
                        $string13 = /\/Responder\/Responder\.conf/
                        $string14 = /\/ridenum\/ridenum\.py/
                        $string15 = /\/shares\-with\-SCF\.txt/
                        $string16 = /\/smb\-cmds\.txt/
                        $string17 = /\/smb\-signing\-disabled\-hosts\.txt/
                        $string18 = /\/theHarvester\.py/
                        $string19 = "/virtualenvs/icebreaker"
                        $string20 = /\\icebreaker\.py/ nocase ascii wide
                        $string21 = /1mil\-AD\-passwords\.txt/ nocase ascii wide
                        $string22 = "byt3bl33d3r/DeathStar" nocase ascii wide
                        $string23 = "CoreSecurity/impacket/" nocase ascii wide
                        $string24 = "DanMcInerney/Empire" nocase ascii wide
                        $string25 = "DanMcInerney/icebreaker" nocase ascii wide
                        $string26 = "DanMcInerney/theHarvester" nocase ascii wide
                        $string27 = /found\-passwords\.txt/ nocase ascii wide
                        $string28 = /https\:\/\/0\.0\.0\.0\:1337/ nocase ascii wide
                        $string29 = "icebreaker:P@ssword123456" nocase ascii wide
                        $string30 = /icebreaker\-master\.zip/ nocase ascii wide
                        $string31 = /icebreaker\-scan\.xml/ nocase ascii wide
                        $string32 = "Invoke-Cats -pwds" nocase ascii wide
                        $string33 = /Invoke\-Cats\.ps1/ nocase ascii wide
                        $string34 = /Invoke\-Pwds\.ps1/ nocase ascii wide
                        $string35 = /logs\/Responder\-Session\.log/ nocase ascii wide
                        $string36 = /logs\/ridenum\.log/ nocase ascii wide
                        $string37 = /logs\/shares\-with\-SCF\.txt/ nocase ascii wide
                        $string38 = /logs\/theHarvester\.py\.log/ nocase ascii wide
                        $string39 = "net localgroup administrators icebreaker" nocase ascii wide
                        $string40 = "net user /add icebreaker " nocase ascii wide
                        $string41 = /ntlmrelayx\.py\.log/ nocase ascii wide
                        $string42 = "sudo tmux new -s icebreaker"
                        $string43 = /\-\-wordlist\=.{0,100}\-passwords\.txt/ nocase ascii wide
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