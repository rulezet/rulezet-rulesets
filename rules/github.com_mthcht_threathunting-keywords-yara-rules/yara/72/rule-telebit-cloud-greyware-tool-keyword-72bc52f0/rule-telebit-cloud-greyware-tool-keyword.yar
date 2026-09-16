rule rule_telebit_cloud_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'telebit.cloud' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "telebit.cloud"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_telebit_cloud_greyware_tool_keyword = /\.config\/telebit\/telebitd\.yml/ nocase ascii wide
                        $string2_telebit_cloud_greyware_tool_keyword = /\/cloud\.telebit\.remote\.plist/
                        $string3_telebit_cloud_greyware_tool_keyword = "/opt/telebit"
                        $string4_telebit_cloud_greyware_tool_keyword = "/telebit http "
                        $string5_telebit_cloud_greyware_tool_keyword = /\/telebit\.js\.git/
                        $string6_telebit_cloud_greyware_tool_keyword = /\/telebit\.service/
                        $string7_telebit_cloud_greyware_tool_keyword = "/telebit/var/log/"
                        $string8_telebit_cloud_greyware_tool_keyword = /\/telebit\-remote\.js/
                        $string9_telebit_cloud_greyware_tool_keyword = /bin\/telebit\.js/ nocase ascii wide
                        $string10_telebit_cloud_greyware_tool_keyword = /cloud\.telebit\.remot/ nocase ascii wide
                        $string11_telebit_cloud_greyware_tool_keyword = /https\:\/\/.{0,100}\.telebit\.io/ nocase ascii wide
                        $string12_telebit_cloud_greyware_tool_keyword = /https\:\/\/get\.telebit\.io/ nocase ascii wide
                        $string13_telebit_cloud_greyware_tool_keyword = "install -g telebit" nocase ascii wide
                        $string14_telebit_cloud_greyware_tool_keyword = /netcat\s.{0,100}\.telebit\.io/ nocase ascii wide
                        $string15_telebit_cloud_greyware_tool_keyword = /ssh\s\-o\s.{0,100}\.telebit\.io/ nocase ascii wide
                        $string16_telebit_cloud_greyware_tool_keyword = /ssh.{0,100}\.telebit\.cloud/ nocase ascii wide
                        $string17_telebit_cloud_greyware_tool_keyword = "telebit ssh auto" nocase ascii wide
                        $string18_telebit_cloud_greyware_tool_keyword = "telebit tcp " nocase ascii wide
                        $string19_telebit_cloud_greyware_tool_keyword = "--user-unit=telebit" nocase ascii wide
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