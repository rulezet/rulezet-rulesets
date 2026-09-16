rule RemotePotato0
{
    meta:
        description = "Detection patterns for the tool 'RemotePotato0' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemotePotato0"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " printing the golden data, format inspired by Responder :D" nocase ascii wide
                        $string2 = /\sRemotePotato0\.zip/ nocase ascii wide
                        $string3 = " RogueOxidResolver must be run remotely" nocase ascii wide
                        $string4 = /\s\-s\s127\.0\.0\.1\s\-e\s.{0,100}\s\-a\sconnect\s\-u\sntlm/ nocase ascii wide
                        $string5 = /\#include\s\\"RogueOxidResolver\.h/ nocase ascii wide
                        $string6 = /\.py\s\-t\sldap\:\/\/.{0,100}\s\-\-no\-wcf\-server\s\-\-escalate\-user\s/ nocase ascii wide
                        $string7 = /\/RemotePotato0\.git/ nocase ascii wide
                        $string8 = /\/RemotePotato0\.zip/ nocase ascii wide
                        $string9 = /\[\!\]\sCouldn\'t\scapture\sthe\suser\scredential\shash\s\:/ nocase ascii wide
                        $string10 = /\[\!\]\sCouldn\'t\scommunicate\swith\sthe\sfake\sRPC\sServer/ nocase ascii wide
                        $string11 = /\[\!\]\sCouldn\'t\sreceive\sthe\stype2\smessage\sfrom\sthe\sfake\sRPC\sServer/ nocase ascii wide
                        $string12 = /\[\+\]\sRelaying\sseems\ssuccessfull\,\scheck\sntlmrelayx\soutput\!/ nocase ascii wide
                        $string13 = /\[\+\]\sUser\shash\sstolen\!/ nocase ascii wide
                        $string14 = /\\RemotePotato0\.cpp/ nocase ascii wide
                        $string15 = /\\RemotePotato0\.sln/ nocase ascii wide
                        $string16 = /\\RemotePotato0\.zip/ nocase ascii wide
                        $string17 = /\\RemotePotato0\-main\.zip/ nocase ascii wide
                        $string18 = /\\RemotePotato0\-main\\/ nocase ascii wide
                        $string19 = /\\RogueOxidResolver\.cpp/ nocase ascii wide
                        $string20 = /\]\sStarting\sRogueOxidResolver\sRPC\sServer\slistening\son\sport/ nocase ascii wide
                        $string21 = /\]\sStarting\sthe\sNTLM\srelay\sattack\,\slaunch\sntlmrelayx\son\s/ nocase ascii wide
                        $string22 = /\]\sStarting\sthe\sRPC\sserver\sto\scapture\sthe\scredentials\shash\sfrom\sthe\suser\sauthentication\!\!/ nocase ascii wide
                        $string23 = "1c6b60ff20f7c26a7436d966fc741ecd05dc2b3326de1ebcd7fcf6142ac24409" nocase ascii wide
                        $string24 = "antonioCoco/RemotePotato0" nocase ascii wide
                        $string25 = "B88B65D3-2689-4E39-892C-7532087174CB" nocase ascii wide
                        $string26 = "Detected a Windows Server version not compatible with JuicyPotato" nocase ascii wide
                        $string27 = /ntlmrelayx\.py/ nocase ascii wide
                        $string28 = /RemotePotato0.{0,100}\@splinter_code\s\&\s\@decoder_it/ nocase ascii wide
                        $string29 = /RemotePotato0\.exe/ nocase ascii wide
                        $string30 = /RogueOxidResolver\scan\sbe\srun\slocally\son\s127\.0\.0\.1/ nocase ascii wide
                        $string31 = /sudo\ssocat\s\-v\sTCP\-LISTEN\:135.{0,100}rogueOxidResolverPort/
                        $string32 = /you\scannot\srun\sthe\sRogueOxidResolver\son\s127\.0\.0\.1/ nocase ascii wide
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