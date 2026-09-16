rule wraith
{
    meta:
        description = "Detection patterns for the tool 'wraith' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wraith"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\swraith\.py/ nocase ascii wide
                        $string2 = /\swraith\-server\.py/ nocase ascii wide
                        $string3 = /\swraith\-server_v.{0,100}\.py/ nocase ascii wide
                        $string4 = "\"active_wraith_clients\"" nocase ascii wide
                        $string5 = "/assets/wraith-scripts/" nocase ascii wide
                        $string6 = /\/wraith\.git/ nocase ascii wide
                        $string7 = /\/wraith\.py/ nocase ascii wide
                        $string8 = /\/wraith\-master\.zip/ nocase ascii wide
                        $string9 = "/wraith-RAT-payloads" nocase ascii wide
                        $string10 = /\/wraith\-RAT\-payloads\.git/ nocase ascii wide
                        $string11 = /\/wraith\-server\.py/ nocase ascii wide
                        $string12 = /\/wraith\-server_v.{0,100}\.py/ nocase ascii wide
                        $string13 = /\\wraith\.py/ nocase ascii wide
                        $string14 = /\\wraith\-master\.zip/ nocase ascii wide
                        $string15 = /\\wraith\-RAT\-payloads/ nocase ascii wide
                        $string16 = /\\wraith\-server\.py/ nocase ascii wide
                        $string17 = /\\wraith\-server_v.{0,100}\.py/ nocase ascii wide
                        $string18 = "<h1>Wraith Login" nocase ascii wide
                        $string19 = "<title>Wraith Login</title>" nocase ascii wide
                        $string20 = "04eb0f500553c9d58de8f5a8bb102cba7dcb0d1e9a77baa4227237c49a5e81d8" nocase ascii wide
                        $string21 = "309c23d800972611948a5980921fdf6e78bdda2fc4d30f4dba3bd8c970a17e94" nocase ascii wide
                        $string22 = "76b70dcbcb1d45935f1b12eef38162b812f88bb4ff89a07a46609d879019103e" nocase ascii wide
                        $string23 = /dev\.l1qu1d\.net\/wraith\-labs\/wraith/ nocase ascii wide
                        $string24 = /login\.php\?LOGMEOUTPLZ\=true/ nocase ascii wide
                        $string25 = /script_main\(wraith\,\scmdline\)/ nocase ascii wide
                        $string26 = "Successfully installed wraith to run on startup " nocase ascii wide
                        $string27 = "TR-SLimey/wraith-RAT" nocase ascii wide
                        $string28 = "wraith-labs/wraith" nocase ascii wide
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