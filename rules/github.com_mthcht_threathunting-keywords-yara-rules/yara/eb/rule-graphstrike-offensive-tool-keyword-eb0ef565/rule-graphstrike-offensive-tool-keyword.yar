rule rule_GraphStrike_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GraphStrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphStrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GraphStrike_offensive_tool_keyword = /\sGraphStrike\.py/ nocase ascii wide
                        $string2_GraphStrike_offensive_tool_keyword = /\.cobaltstrike\.beacon_keys/ nocase ascii wide
                        $string3_GraphStrike_offensive_tool_keyword = /\/GraphStrike\.cna/ nocase ascii wide
                        $string4_GraphStrike_offensive_tool_keyword = /\/GraphStrike\.git/ nocase ascii wide
                        $string5_GraphStrike_offensive_tool_keyword = /\/graphstrike\.profile/ nocase ascii wide
                        $string6_GraphStrike_offensive_tool_keyword = /\/GraphStrike\.py/ nocase ascii wide
                        $string7_GraphStrike_offensive_tool_keyword = "/GraphStrike-main/" nocase ascii wide
                        $string8_GraphStrike_offensive_tool_keyword = "/opt/cobaltstrike/"
                        $string9_GraphStrike_offensive_tool_keyword = /\[\+\]\sRandomizing\ssyscall\snames/ nocase ascii wide
                        $string10_GraphStrike_offensive_tool_keyword = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
                        $string11_GraphStrike_offensive_tool_keyword = /\\GraphLdr\.x64\.bin/ nocase ascii wide
                        $string12_GraphStrike_offensive_tool_keyword = /\\GraphStrike\.cna/ nocase ascii wide
                        $string13_GraphStrike_offensive_tool_keyword = /\\GraphStrike\.py/ nocase ascii wide
                        $string14_GraphStrike_offensive_tool_keyword = /\\GraphStrike\-main\\/ nocase ascii wide
                        $string15_GraphStrike_offensive_tool_keyword = /change_sandbox_evasion_method\(/ nocase ascii wide
                        $string16_GraphStrike_offensive_tool_keyword = /GraphLdr\.x64\.bin/ nocase ascii wide
                        $string17_GraphStrike_offensive_tool_keyword = /GraphLdr\.x64\.exe/ nocase ascii wide
                        $string18_GraphStrike_offensive_tool_keyword = "GraphStrike Server is running and checking SharePoint for Beacon traffic" nocase ascii wide
                        $string19_GraphStrike_offensive_tool_keyword = /GraphStrike\.py\s/ nocase ascii wide
                        $string20_GraphStrike_offensive_tool_keyword = /Lost\sconnection\sto\steam\sserver\!\sSleeping\s60\ssecond\sand\sretrying\?/ nocase ascii wide
                        $string21_GraphStrike_offensive_tool_keyword = /Mozilla\/6\.0\s\(Windows\sNT\s10\.0\;\sWin64\;\sx64\)\sAppleWebKit\/537\.36\s\(KHTML\,\slike\sGecko\)\sChrome\/103\.0\.0\.0\sSafari\/537\.36/ nocase ascii wide
                        $string22_GraphStrike_offensive_tool_keyword = "RedSiege/GraphStrike" nocase ascii wide
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