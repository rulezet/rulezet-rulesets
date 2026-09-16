rule SspiUacBypass
{
    meta:
        description = "Detection patterns for the tool 'SspiUacBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SspiUacBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " - Bypassing UAC with SSPI Datagram Contexts" nocase ascii wide
                        $string2 = " SspiUacBypass " nocase ascii wide
                        $string3 = /\/SspiUacBypass\.git/ nocase ascii wide
                        $string4 = /\\bypassuac\.txt/ nocase ascii wide
                        $string5 = "5F4DC47F-7819-4528-9C16-C88F1BE97EC5" nocase ascii wide
                        $string6 = "antonioCoco/SspiUacBypass" nocase ascii wide
                        $string7 = /Bypass\sSuccess\!\sNow\simpersonating\sthe\sforged\stoken.{0,100}\sLoopback\snetwork\sauth\sshould\sbe\sseen\sas\selevated\snow/ nocase ascii wide
                        $string8 = "ea49111ee3bf716e9f4643f95b5df19fd8bd7376464b2795dcfc5e07ddda35eb" nocase ascii wide
                        $string9 = "Forging a token from a fake Network Authentication through Datagram Contexts" nocase ascii wide
                        $string10 = /Invoking\sCreateSvcRpc\s\(by\s\@x86matthew/ nocase ascii wide
                        $string11 = /SspiUacBypass\.cpp/ nocase ascii wide
                        $string12 = /SspiUacBypass\.exe/ nocase ascii wide
                        $string13 = "SspiUacBypass-main" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}