rule rule_tunnelmole_client_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tunnelmole-client' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnelmole-client"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tunnelmole_client_greyware_tool_keyword = /\stunnelmole\.bundle\.js/ nocase ascii wide
                        $string2_tunnelmole_client_greyware_tool_keyword = /\.bin\/tmole/ nocase ascii wide
                        $string3_tunnelmole_client_greyware_tool_keyword = /\.bin\/tunnelmole/ nocase ascii wide
                        $string4_tunnelmole_client_greyware_tool_keyword = /\/bin\/tunnelmole\.js/
                        $string5_tunnelmole_client_greyware_tool_keyword = /\/tunnelmole\.js/ nocase ascii wide
                        $string6_tunnelmole_client_greyware_tool_keyword = /\/tunnelmole\-client\.git/ nocase ascii wide
                        $string7_tunnelmole_client_greyware_tool_keyword = "/tunnelmole-service" nocase ascii wide
                        $string8_tunnelmole_client_greyware_tool_keyword = /\/tunnelmole\-service\.git/ nocase ascii wide
                        $string9_tunnelmole_client_greyware_tool_keyword = /\\\.tmole\.sh\\/ nocase ascii wide
                        $string10_tunnelmole_client_greyware_tool_keyword = /\\tmole\.exe/ nocase ascii wide
                        $string11_tunnelmole_client_greyware_tool_keyword = /\\tunnelmole\.bundle\.js/ nocase ascii wide
                        $string12_tunnelmole_client_greyware_tool_keyword = "25191b226ad7ef139f81890c531b0c606c5645bbca6f149b3679b06c73e6cddc" nocase ascii wide
                        $string13_tunnelmole_client_greyware_tool_keyword = "2b4328c30b58ecaf6febe1d7225b543b8886dcb4d8295be5973e6dc36f62c0f2" nocase ascii wide
                        $string14_tunnelmole_client_greyware_tool_keyword = /dashboard\.tunnelmole\.com/ nocase ascii wide
                        $string15_tunnelmole_client_greyware_tool_keyword = /f38fg\.tunnelmole\.net/ nocase ascii wide
                        $string16_tunnelmole_client_greyware_tool_keyword = /http\:\/\/.{0,100}\.tunnelmole\.net/ nocase ascii wide
                        $string17_tunnelmole_client_greyware_tool_keyword = /https\:\/\/.{0,100}\.tunnelmole\.net/ nocase ascii wide
                        $string18_tunnelmole_client_greyware_tool_keyword = /https\:\/\/tunnelmole\.com\/docs/ nocase ascii wide
                        $string19_tunnelmole_client_greyware_tool_keyword = /https\:\/\/tunnelmole\.com\/downloads\/tmole\.exe/ nocase ascii wide
                        $string20_tunnelmole_client_greyware_tool_keyword = /install\.tunnelmole\.com/ nocase ascii wide
                        $string21_tunnelmole_client_greyware_tool_keyword = /node\stunnelmole\.js/ nocase ascii wide
                        $string22_tunnelmole_client_greyware_tool_keyword = "npm install -g tunnelmole" nocase ascii wide
                        $string23_tunnelmole_client_greyware_tool_keyword = /npm\sinstall.{0,100}\stunnelmole/ nocase ascii wide
                        $string24_tunnelmole_client_greyware_tool_keyword = /\-\-output\stmole\.exe/ nocase ascii wide
                        $string25_tunnelmole_client_greyware_tool_keyword = "robbie-cahill/tunnelmole-client" nocase ascii wide
                        $string26_tunnelmole_client_greyware_tool_keyword = /service\.tunnelmole\.com/ nocase ascii wide
                        $string27_tunnelmole_client_greyware_tool_keyword = "tmole - Share your local server with a Public URL" nocase ascii wide
                        $string28_tunnelmole_client_greyware_tool_keyword = "tmole --set-api-key " nocase ascii wide
                        $string29_tunnelmole_client_greyware_tool_keyword = "'Tunnelmole Service listening on http port " nocase ascii wide
                        $string30_tunnelmole_client_greyware_tool_keyword = "Tunnelmole Service listening on websocket port " nocase ascii wide
                        $string31_tunnelmole_client_greyware_tool_keyword = "tunnelmole/cjs" nocase ascii wide
                        $string32_tunnelmole_client_greyware_tool_keyword = "TUNNELMOLE_TELEMETRY" nocase ascii wide
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