rule tunnelmole_client
{
    meta:
        description = "Detection patterns for the tool 'tunnelmole-client' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnelmole-client"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\stunnelmole\.bundle\.js/ nocase ascii wide
                        $string2 = /\.bin\/tmole/ nocase ascii wide
                        $string3 = /\.bin\/tunnelmole/ nocase ascii wide
                        $string4 = /\/bin\/tunnelmole\.js/
                        $string5 = /\/tunnelmole\.js/ nocase ascii wide
                        $string6 = /\/tunnelmole\-client\.git/ nocase ascii wide
                        $string7 = "/tunnelmole-service" nocase ascii wide
                        $string8 = /\/tunnelmole\-service\.git/ nocase ascii wide
                        $string9 = /\\\.tmole\.sh\\/ nocase ascii wide
                        $string10 = /\\tmole\.exe/ nocase ascii wide
                        $string11 = /\\tunnelmole\.bundle\.js/ nocase ascii wide
                        $string12 = "25191b226ad7ef139f81890c531b0c606c5645bbca6f149b3679b06c73e6cddc" nocase ascii wide
                        $string13 = "2b4328c30b58ecaf6febe1d7225b543b8886dcb4d8295be5973e6dc36f62c0f2" nocase ascii wide
                        $string14 = /dashboard\.tunnelmole\.com/ nocase ascii wide
                        $string15 = /f38fg\.tunnelmole\.net/ nocase ascii wide
                        $string16 = /http\:\/\/.{0,100}\.tunnelmole\.net/ nocase ascii wide
                        $string17 = /https\:\/\/.{0,100}\.tunnelmole\.net/ nocase ascii wide
                        $string18 = /https\:\/\/tunnelmole\.com\/docs/ nocase ascii wide
                        $string19 = /https\:\/\/tunnelmole\.com\/downloads\/tmole\.exe/ nocase ascii wide
                        $string20 = /install\.tunnelmole\.com/ nocase ascii wide
                        $string21 = /node\stunnelmole\.js/ nocase ascii wide
                        $string22 = "npm install -g tunnelmole" nocase ascii wide
                        $string23 = /npm\sinstall.{0,100}\stunnelmole/ nocase ascii wide
                        $string24 = /\-\-output\stmole\.exe/ nocase ascii wide
                        $string25 = "robbie-cahill/tunnelmole-client" nocase ascii wide
                        $string26 = /service\.tunnelmole\.com/ nocase ascii wide
                        $string27 = "tmole - Share your local server with a Public URL" nocase ascii wide
                        $string28 = "tmole --set-api-key " nocase ascii wide
                        $string29 = "'Tunnelmole Service listening on http port " nocase ascii wide
                        $string30 = "Tunnelmole Service listening on websocket port " nocase ascii wide
                        $string31 = "tunnelmole/cjs" nocase ascii wide
                        $string32 = "TUNNELMOLE_TELEMETRY" nocase ascii wide
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