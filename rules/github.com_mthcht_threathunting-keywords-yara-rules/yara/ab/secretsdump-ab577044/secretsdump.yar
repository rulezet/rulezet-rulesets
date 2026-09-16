rule secretsdump
{
    meta:
        description = "Detection patterns for the tool 'secretsdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "secretsdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -just-dc-ntlm " nocase ascii wide
                        $string2 = " -just-dc-user " nocase ascii wide
                        $string3 = /\/cached\-domain\-credentials\.html/ nocase ascii wide
                        $string4 = /\/decrypting\-lsa\-secrets\.html/ nocase ascii wide
                        $string5 = /\/syskey\-and\-sam\.html/ nocase ascii wide
                        $string6 = /\]\sDumping\ssecrets\sfor\:\s.{0,100}Username\:\s/ nocase ascii wide
                        $string7 = "29cf4b68c34663281bebc94f62c92282ca351839032140fcb2b0266d44a8bc84" nocase ascii wide
                        $string8 = "fin3ss3g0d/secretsdump" nocase ascii wide
                        $string9 = /impacket\.examples\.secretsdump/ nocase ascii wide
                        $string10 = "Policy SPN target name validation might be restricting full DRSUAPI dump" nocase ascii wide
                        $string11 = /resuming\sa\sprevious\sNTDS\.DIT\sdump\ssession/ nocase ascii wide
                        $string12 = /secretsdump\.py/ nocase ascii wide
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