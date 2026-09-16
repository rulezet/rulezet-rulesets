rule DomainPasswordSpray
{
    meta:
        description = "Detection patterns for the tool 'DomainPasswordSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DomainPasswordSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-UserList\s.{0,100}\s\-Domain\s.{0,100}\s\-PasswordList\s.{0,100}\s\-OutFile\s/ nocase ascii wide
                        $string2 = /\/DomainPasswordSpray\.git/ nocase ascii wide
                        $string3 = /\\DomainPasswordSpray\\/ nocase ascii wide
                        $string4 = /\\DomainPasswordSpray\-master/ nocase ascii wide
                        $string5 = /\\sprayed\-creds\.txt/ nocase ascii wide
                        $string6 = /\\valid\-creds\.txt/ nocase ascii wide
                        $string7 = /\]\sAny\spasswords\sthat\swere\ssuccessfully\ssprayed\shave\sbeen\soutput\sto\s/ nocase ascii wide
                        $string8 = /\]\sPassword\sspraying\shas\sbegun\swith\s/ nocase ascii wide
                        $string9 = /\]\sPassword\sspraying\sis\scomplete/ nocase ascii wide
                        $string10 = "1a3c4069-8c11-4336-bef8-9a43c0ba60e2" nocase ascii wide
                        $string11 = "433d59580b95a3e3b82364729aac65643385eb4500c46eae2aab1c0567df03e6" nocase ascii wide
                        $string12 = /Cancelling\sthe\spassword\sspray\./ nocase ascii wide
                        $string13 = "dafthack/DomainPasswordSpray" nocase ascii wide
                        $string14 = "DomainPasswordSpray" nocase ascii wide
                        $string15 = /DomainPasswordSpray\.ps1/ nocase ascii wide
                        $string16 = /DomainPasswordSpray\.psm1/ nocase ascii wide
                        $string17 = /Get\-DomainUserList\s\-Domain\s.{0,100}\s\-RemoveDisabled\s/ nocase ascii wide
                        $string18 = "Invoke-DomainPasswordSpray" nocase ascii wide
                        $string19 = "Invoke-DomainPasswordSpray" nocase ascii wide
                        $string20 = "mdavis332/DomainPasswordSpray" nocase ascii wide
                        $string21 = "PasswordSpray " nocase ascii wide
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