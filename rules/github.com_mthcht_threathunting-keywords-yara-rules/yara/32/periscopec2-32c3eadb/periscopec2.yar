rule PeriscopeC2
{
    meta:
        description = "Detection patterns for the tool 'PeriscopeC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PeriscopeC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\supload_c2profiles\.py/ nocase ascii wide
                        $string2 = /\/c2profiles\.zip/ nocase ascii wide
                        $string3 = /\/conf\/c2profiles\.json/
                        $string4 = /\/data\/assemblies\/SharpPick\.exe/
                        $string5 = /\/data\/assemblies\/SharpSendEmail\.exe/
                        $string6 = /\/data\/assemblies\/SharpView\.exe/
                        $string7 = "/data/dll/mimikatz/mimikatz"
                        $string8 = "/data/dll/PromptCreds/PromptCreds"
                        $string9 = /\/opt\/HttpRedirector\/conf\/periscope\.key/
                        $string10 = /\/opt\/periscope\/ControlCenter\/db\/periscope\.db/
                        $string11 = /\/raw\/master\/Release\/Happy\.exe/ nocase ascii wide
                        $string12 = /\/raw\/master\/Release\/Happy_x64\.exe/ nocase ascii wide
                        $string13 = /\/upload_c2profiles\.py/ nocase ascii wide
                        $string14 = /\\periscope_release_x64\.exe/ nocase ascii wide
                        $string15 = "5531A5C5-8710-48AD-BEFE-88E26F6CF798" nocase ascii wide
                        $string16 = "6DE0DE7E-A81D-4194-B36A-3E67283FCABE" nocase ascii wide
                        $string17 = "72DCE01A-B6EC-4AC3-A98B-D5C44D532626" nocase ascii wide
                        $string18 = "ABF5940C-60AC-4892-B3F0-0F9262C550B3" nocase ascii wide
                        $string19 = "AF7F4404-C746-43EC-86EA-8405473C95C9" nocase ascii wide
                        $string20 = "api_username = \"\"redtiger1337\"\"" nocase ascii wide
                        $string21 = /bdtryujndyund6e5\.azurewebsites\.net/ nocase ascii wide
                        $string22 = "CBAB0FE9-F4C0-49F2-90B1-7F34593F705A" nocase ascii wide
                        $string23 = "D0DF8E42-3CED-4A5F-BB28-0C348B56BC79" nocase ascii wide
                        $string24 = "EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI" nocase ascii wide
                        $string25 = "F5B94815-D623-4947-9A2B-88ABAF7FA6D9" nocase ascii wide
                        $string26 = "http://localhost:4430/hello" nocase ascii wide
                        $string27 = /mifunftyundf6deg\.azurewebsites\.net/ nocase ascii wide
                        $string28 = /mimikatz_x64\.dll/ nocase ascii wide
                        $string29 = /mimikatz_x86\.dll/ nocase ascii wide
                        $string30 = /nbdytundtyud5dey\.azurewebsites\.net/ nocase ascii wide
                        $string31 = /PeriscopeCLI\.SelectedHost\.HostData\.RegistryEntries/ nocase ascii wide
                        $string32 = /PromptCreds_x64\.dll/ nocase ascii wide
                        $string33 = /PromptCreds_x86\.dll/ nocase ascii wide
                        $string34 = "PwDLwAGAAkELwAGAK8ALwAOAE8FPgUGAG8FeQMGAK0ChwUOAC0FSAQOAMsASAQGABAFeQMAAAAAHAAAAAAAAQABAAAAEABxAxIDQQABAAEAUCAAAAAAkQA5ALQAAQDsIAAAAACRAOQD" nocase ascii wide
                        $string35 = /raheemabass55\@gmail\.com/ nocase ascii wide
                        $string36 = /ServiceName\s\=\s\\"\\"\[C2ProfileService\]/ nocase ascii wide
                        $string37 = /SG\.3xuRB22RTYaelD4sHiEBMw\.2wquktoAczDucX_KPgxXuo0xp\-h1hMnJ\-DLzBKOmIok/ nocase ascii wide
                        $string38 = /stager\/happy_x64\.txt/ nocase ascii wide
                        $string39 = /stager\/happy_x86\.txt/ nocase ascii wide
                        $string40 = /stager\/sad_x64\.txt/ nocase ascii wide
                        $string41 = /stager\/sad_x86\.txt/ nocase ascii wide
                        $string42 = /vpfxasdwnuewedfn\.azurewebsites\.net/ nocase ascii wide
                        $string43 = /WatermelonMakeup\.azurewebsites\.net/ nocase ascii wide
                        $string44 = /ytmrdnutyd5drtny\.azurewebsites\.net/ nocase ascii wide
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