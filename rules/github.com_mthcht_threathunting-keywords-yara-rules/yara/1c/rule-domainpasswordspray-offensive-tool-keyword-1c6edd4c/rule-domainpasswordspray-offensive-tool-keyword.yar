rule rule_DomainPasswordSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DomainPasswordSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DomainPasswordSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DomainPasswordSpray_offensive_tool_keyword = /\s\-UserList\s.{0,100}\s\-Domain\s.{0,100}\s\-PasswordList\s.{0,100}\s\-OutFile\s/ nocase ascii wide
                        $string2_DomainPasswordSpray_offensive_tool_keyword = /\/DomainPasswordSpray\.git/ nocase ascii wide
                        $string3_DomainPasswordSpray_offensive_tool_keyword = /\\DomainPasswordSpray\\/ nocase ascii wide
                        $string4_DomainPasswordSpray_offensive_tool_keyword = /\\DomainPasswordSpray\-master/ nocase ascii wide
                        $string5_DomainPasswordSpray_offensive_tool_keyword = /\\sprayed\-creds\.txt/ nocase ascii wide
                        $string6_DomainPasswordSpray_offensive_tool_keyword = /\\valid\-creds\.txt/ nocase ascii wide
                        $string7_DomainPasswordSpray_offensive_tool_keyword = /\]\sAny\spasswords\sthat\swere\ssuccessfully\ssprayed\shave\sbeen\soutput\sto\s/ nocase ascii wide
                        $string8_DomainPasswordSpray_offensive_tool_keyword = /\]\sPassword\sspraying\shas\sbegun\swith\s/ nocase ascii wide
                        $string9_DomainPasswordSpray_offensive_tool_keyword = /\]\sPassword\sspraying\sis\scomplete/ nocase ascii wide
                        $string10_DomainPasswordSpray_offensive_tool_keyword = "1a3c4069-8c11-4336-bef8-9a43c0ba60e2" nocase ascii wide
                        $string11_DomainPasswordSpray_offensive_tool_keyword = "433d59580b95a3e3b82364729aac65643385eb4500c46eae2aab1c0567df03e6" nocase ascii wide
                        $string12_DomainPasswordSpray_offensive_tool_keyword = /Cancelling\sthe\spassword\sspray\./ nocase ascii wide
                        $string13_DomainPasswordSpray_offensive_tool_keyword = "dafthack/DomainPasswordSpray" nocase ascii wide
                        $string14_DomainPasswordSpray_offensive_tool_keyword = "DomainPasswordSpray" nocase ascii wide
                        $string15_DomainPasswordSpray_offensive_tool_keyword = /DomainPasswordSpray\.ps1/ nocase ascii wide
                        $string16_DomainPasswordSpray_offensive_tool_keyword = /DomainPasswordSpray\.psm1/ nocase ascii wide
                        $string17_DomainPasswordSpray_offensive_tool_keyword = /Get\-DomainUserList\s\-Domain\s.{0,100}\s\-RemoveDisabled\s/ nocase ascii wide
                        $string18_DomainPasswordSpray_offensive_tool_keyword = "Invoke-DomainPasswordSpray" nocase ascii wide
                        $string19_DomainPasswordSpray_offensive_tool_keyword = "Invoke-DomainPasswordSpray" nocase ascii wide
                        $string20_DomainPasswordSpray_offensive_tool_keyword = "mdavis332/DomainPasswordSpray" nocase ascii wide
                        $string21_DomainPasswordSpray_offensive_tool_keyword = "PasswordSpray " nocase ascii wide
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