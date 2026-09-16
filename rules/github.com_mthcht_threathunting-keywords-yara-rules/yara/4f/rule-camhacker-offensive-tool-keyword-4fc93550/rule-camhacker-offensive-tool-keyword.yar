rule rule_CamHacker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CamHacker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CamHacker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CamHacker_offensive_tool_keyword = " camhacker " nocase ascii wide
                        $string2_CamHacker_offensive_tool_keyword = " camhacker:/CamHacker" nocase ascii wide
                        $string3_CamHacker_offensive_tool_keyword = /\stermux\-chroot\s.{0,100}\/cloudflared/ nocase ascii wide
                        $string4_CamHacker_offensive_tool_keyword = /\$Hc2\$w\$c\$rQW\$d\$s\$w\$b\$Hc2\$v\$xZp\$f\$w\$V9z\$rQW\$L\$U\$xZp/ nocase ascii wide
                        $string5_CamHacker_offensive_tool_keyword = /\$HOME\/\.tunneler/ nocase ascii wide
                        $string6_CamHacker_offensive_tool_keyword = /\$N0q\$x\$Hc2\$rQW/ nocase ascii wide
                        $string7_CamHacker_offensive_tool_keyword = /\$tunneler_dir\/loclx\.log/ nocase ascii wide
                        $string8_CamHacker_offensive_tool_keyword = /\.tunneler\/cf\.log/ nocase ascii wide
                        $string9_CamHacker_offensive_tool_keyword = /\.tunneler\/cloudflared/ nocase ascii wide
                        $string10_CamHacker_offensive_tool_keyword = /\.tunneler\/loclx/ nocase ascii wide
                        $string11_CamHacker_offensive_tool_keyword = /\.tunneler\/loclx\.log/ nocase ascii wide
                        $string12_CamHacker_offensive_tool_keyword = /\/\.localxpose\/\.access/
                        $string13_CamHacker_offensive_tool_keyword = /\/CamHacker\-.{0,100}\.png/ nocase ascii wide
                        $string14_CamHacker_offensive_tool_keyword = /\/CamHacker\.git/ nocase ascii wide
                        $string15_CamHacker_offensive_tool_keyword = /\/releases\/latest\/download\/cloudflared\-darwin\-amd64\.tgz/
                        $string16_CamHacker_offensive_tool_keyword = /\[CamHacker\]/ nocase ascii wide
                        $string17_CamHacker_offensive_tool_keyword = /\\CamHacker\\/ nocase ascii wide
                        $string18_CamHacker_offensive_tool_keyword = "=ogIXFlckIzYIRCekEHMORiIgwWY2VmCpICcahHJVRCTkcVUyRie5YFJ3RiZkAnW4RidkIzYIRiYkcHJzRCZkcVUyRyYkcHJyMGSkICIsFmdlhCJ9gnC" nocase ascii wide
                        $string19_CamHacker_offensive_tool_keyword = "CamHacker has a new update!" nocase ascii wide
                        $string20_CamHacker_offensive_tool_keyword = "CamHacker updated successfully" nocase ascii wide
                        $string21_CamHacker_offensive_tool_keyword = /CamHacker\/releases\/latest\/download\/websites\.zip/ nocase ascii wide
                        $string22_CamHacker_offensive_tool_keyword = "Cloudflared and Loclx have started successfully!" nocase ascii wide
                        $string23_CamHacker_offensive_tool_keyword = "Cloudflared has started successfully!" nocase ascii wide
                        $string24_CamHacker_offensive_tool_keyword = /Device\sarchitecture\sunknown\.\sDownload\scloudflared\/loclx\smanually/ nocase ascii wide
                        $string25_CamHacker_offensive_tool_keyword = "Don't_blindly_trust_obfuscated_code_it_might_do_something_bad" nocase ascii wide
                        $string26_CamHacker_offensive_tool_keyword = "Enter your loclx authtoken:" nocase ascii wide
                        $string27_CamHacker_offensive_tool_keyword = "Hey Dear! You Have Won Free Rs 399 Jio Recharge" nocase ascii wide
                        $string28_CamHacker_offensive_tool_keyword = /https\:\/\/api\.localxpose\.io\/api\/v2\/downloads\/loclx\-darwin\-amd64\.zip/
                        $string29_CamHacker_offensive_tool_keyword = "https://best-wishes-to-you" nocase ascii wide
                        $string30_CamHacker_offensive_tool_keyword = "https://free-399rs-jio-recharge" nocase ascii wide
                        $string31_CamHacker_offensive_tool_keyword = "https://join-zoom-online-meeting" nocase ascii wide
                        $string32_CamHacker_offensive_tool_keyword = /https\:\/\/raw\.githubusercontent\.com\/KasRoudra\/CamHacker/ nocase ascii wide
                        $string33_CamHacker_offensive_tool_keyword = "https://watch-youtube-videos-live" nocase ascii wide
                        $string34_CamHacker_offensive_tool_keyword = "KasRoudra/CamHacker" nocase ascii wide
                        $string35_CamHacker_offensive_tool_keyword = /kasroudrard\@gmail\.com/ nocase ascii wide
                        $string36_CamHacker_offensive_tool_keyword = "Starting php server at localhost:" nocase ascii wide
                        $string37_CamHacker_offensive_tool_keyword = "Tunneling failed! Start your own port forwarding/tunneling service at port " nocase ascii wide
                        $string38_CamHacker_offensive_tool_keyword = /unzip\swebsites\.zip\s\-d\ssites\s\>\s\/dev\/null/ nocase ascii wide
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