rule rule_hak5_cloudc2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hak5 cloudc2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hak5 cloudc2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hak5_cloudc2_offensive_tool_keyword = "/api/sites/1/devices/1/crocconfig" nocase ascii wide
                        $string2_hak5_cloudc2_offensive_tool_keyword = "/api/sites/1/devices/1/deviceloot" nocase ascii wide
                        $string3_hak5_cloudc2_offensive_tool_keyword = "/api/sites/1/devices/1/keystrokes/" nocase ascii wide
                        $string4_hak5_cloudc2_offensive_tool_keyword = "/api/sites/1/devices/1/matchpayloads" nocase ascii wide
                        $string5_hak5_cloudc2_offensive_tool_keyword = /\/c2\-3\.4\.0\.zip/ nocase ascii wide
                        $string6_hak5_cloudc2_offensive_tool_keyword = /\/c2\-3\.4\.0_amd64_darwin/
                        $string7_hak5_cloudc2_offensive_tool_keyword = /\/c2\-3\.4\.0_amd64_windows\.exe/ nocase ascii wide
                        $string8_hak5_cloudc2_offensive_tool_keyword = /\/c2\-3\.4\.0_arm64_darwin/
                        $string9_hak5_cloudc2_offensive_tool_keyword = /\/c2\-3\.4\.0_i386_windows\.exe/ nocase ascii wide
                        $string10_hak5_cloudc2_offensive_tool_keyword = /\/c2\-3\.4\.0_i386_windows\.exe/ nocase ascii wide
                        $string11_hak5_cloudc2_offensive_tool_keyword = /\/hak5\/cc\-server\/database\.Log/
                        $string12_hak5_cloudc2_offensive_tool_keyword = /\\c2_setup_token\.txt/ nocase ascii wide
                        $string13_hak5_cloudc2_offensive_tool_keyword = /\\c2\-3\.4\.0\.zip/ nocase ascii wide
                        $string14_hak5_cloudc2_offensive_tool_keyword = /\\c2\-3\.4\.0_amd64_windows\.exe/ nocase ascii wide
                        $string15_hak5_cloudc2_offensive_tool_keyword = /\\c2\-3\.4\.0_i386_windows\.exe/ nocase ascii wide
                        $string16_hak5_cloudc2_offensive_tool_keyword = /\\c2\-3\.4\.0_i386_windows\.exe/ nocase ascii wide
                        $string17_hak5_cloudc2_offensive_tool_keyword = /\\fullc2_setup_token\.txt/ nocase ascii wide
                        $string18_hak5_cloudc2_offensive_tool_keyword = /\\Users\\.{0,100}\\c2\.db/ nocase ascii wide
                        $string19_hak5_cloudc2_offensive_tool_keyword = "0a1720f433f5e22118dea9126637364b222b25d812cbb3a9c35fcbc8561650db" nocase ascii wide
                        $string20_hak5_cloudc2_offensive_tool_keyword = "1bf68c433eb8684cda13f16146339666983a0b413243a6708e33dce298bdc23f" nocase ascii wide
                        $string21_hak5_cloudc2_offensive_tool_keyword = "5027474f59bb0dd2c2fcee52a0b689bd3d17068dce81fbbceffa1f52fb732223" nocase ascii wide
                        $string22_hak5_cloudc2_offensive_tool_keyword = "5e6aca1735a130c574685542a7a89b5bab4d4e1bacfe1279ec76189b0bec6fd5" nocase ascii wide
                        $string23_hak5_cloudc2_offensive_tool_keyword = "65dfba472014bb6e61d6f287452dcc099edabf4ba09cb196a27507298077fa75" nocase ascii wide
                        $string24_hak5_cloudc2_offensive_tool_keyword = "752b696841027c3767aa5d6582c03111e7fe0ab05f63905313ae7ce089e8e584" nocase ascii wide
                        $string25_hak5_cloudc2_offensive_tool_keyword = "7d1d37cb68ec4db1391f165074fed471b6a67f1948abeb26751796fad8746640" nocase ascii wide
                        $string26_hak5_cloudc2_offensive_tool_keyword = "a865ea23efd65afc7ab6222c34a2c6f15f827d8e8458f3e7c2c1b0a513182cf1" nocase ascii wide
                        $string27_hak5_cloudc2_offensive_tool_keyword = "b0e4d0a411c1fcf8dad9ca13c9e69660f6f10079d4db982db2167a457ec1e2ce" nocase ascii wide
                        $string28_hak5_cloudc2_offensive_tool_keyword = /c2\.hak5\.org/ nocase ascii wide
                        $string29_hak5_cloudc2_offensive_tool_keyword = "Cloud C2 must be run from the command line" nocase ascii wide
                        $string30_hak5_cloudc2_offensive_tool_keyword = "Cloud C2 will work behind a reverse proxy" nocase ascii wide
                        $string31_hak5_cloudc2_offensive_tool_keyword = "d43660674a9329c64d5a7821c5bd2cdffdb572d95119a6dfee6684bb221bbfb1" nocase ascii wide
                        $string32_hak5_cloudc2_offensive_tool_keyword = "da46e5b2a4a7fb855ec7ca2d53247ab30f87c4cae8b284f2e793c0f716848fe4" nocase ascii wide
                        $string33_hak5_cloudc2_offensive_tool_keyword = /https\:\/\/downloads\.hak5\.org\/cloudc2/ nocase ascii wide
                        $string34_hak5_cloudc2_offensive_tool_keyword = /https\:\/\/shop\.hak5\.org\/pages\/cloud\-c2\-feedback/ nocase ascii wide
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