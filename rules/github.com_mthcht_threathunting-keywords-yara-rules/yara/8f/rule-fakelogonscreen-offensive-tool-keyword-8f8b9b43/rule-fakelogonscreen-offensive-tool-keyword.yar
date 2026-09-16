rule rule_fakelogonscreen_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fakelogonscreen' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fakelogonscreen"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fakelogonscreen_offensive_tool_keyword = /\/fakelogonscreen\.exe/ nocase ascii wide
                        $string2_fakelogonscreen_offensive_tool_keyword = /\/fakelogonscreen\.git/ nocase ascii wide
                        $string3_fakelogonscreen_offensive_tool_keyword = "/fakelogonscreen/releases/download/" nocase ascii wide
                        $string4_fakelogonscreen_offensive_tool_keyword = "/fakelogonscreen/tarball/" nocase ascii wide
                        $string5_fakelogonscreen_offensive_tool_keyword = "/fakelogonscreen/zipball/" nocase ascii wide
                        $string6_fakelogonscreen_offensive_tool_keyword = /\\FakeLogonScreen\.exe/ nocase ascii wide
                        $string7_fakelogonscreen_offensive_tool_keyword = /\\FakeLogonScreen\.sln/ nocase ascii wide
                        $string8_fakelogonscreen_offensive_tool_keyword = /\\fakelogonscreen\-master/ nocase ascii wide
                        $string9_fakelogonscreen_offensive_tool_keyword = "361ec6983d4a8683b685dc4f9b7280e4faebf3a4006cc44c7aab3ea94fe9d2d4" nocase ascii wide
                        $string10_fakelogonscreen_offensive_tool_keyword = "3c39207a61a348efa7dd2db2d85c1e562beedfa8c4593d1d29b7751bc84aad85" nocase ascii wide
                        $string11_fakelogonscreen_offensive_tool_keyword = "5042151210128f823c5cc143d52c6df18ea3bab1f834f7613d57600a6afc543e" nocase ascii wide
                        $string12_fakelogonscreen_offensive_tool_keyword = "532a1b17840d0746c48f98d0f24443bd60111db4f3c5f82872ec5e4e6854438a" nocase ascii wide
                        $string13_fakelogonscreen_offensive_tool_keyword = "7fef9543926764b6093a5ab10ea9d092f9a97acae14dbfd423a7c52cc9454fdb" nocase ascii wide
                        $string14_fakelogonscreen_offensive_tool_keyword = "81e1e9186bb461b669b4bbd4dab4534c980e6d2bc27975e6ec7305bc935cf429" nocase ascii wide
                        $string15_fakelogonscreen_offensive_tool_keyword = "88dc61a50afafe0e0ffff60913d45f2abe2a298c2c8a067fc7044e7251eb9012" nocase ascii wide
                        $string16_fakelogonscreen_offensive_tool_keyword = "98d590b2d7e7ee6c87e251a26f155e9c20765829e8ac291092d139aaa6fae676" nocase ascii wide
                        $string17_fakelogonscreen_offensive_tool_keyword = "bitsadmin/fakelogonscreen" nocase ascii wide
                        $string18_fakelogonscreen_offensive_tool_keyword = "D35A55BD-3189-498B-B72F-DC798172E505" nocase ascii wide
                        $string19_fakelogonscreen_offensive_tool_keyword = "e3a0aa509ad07aab04f9a052a9abc681d414871cd0277deef4b95ea98f1243c8" nocase ascii wide
                        $string20_fakelogonscreen_offensive_tool_keyword = /fakelogonscreen.{0,100}\.zip/ nocase ascii wide
                        $string21_fakelogonscreen_offensive_tool_keyword = /FakeLogonScreen\.csproj/ nocase ascii wide
                        $string22_fakelogonscreen_offensive_tool_keyword = /FakeLogonScreen\.Properties\.Resources/ nocase ascii wide
                        $string23_fakelogonscreen_offensive_tool_keyword = /FakeLogonScreen_trunk\.zip/ nocase ascii wide
                        $string24_fakelogonscreen_offensive_tool_keyword = /FakeLogonScreenToFile\.exe/ nocase ascii wide
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