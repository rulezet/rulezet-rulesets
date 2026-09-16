rule CamHacker
{
    meta:
        description = "Detection patterns for the tool 'CamHacker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CamHacker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " camhacker " nocase ascii wide
                        $string2 = " camhacker:/CamHacker" nocase ascii wide
                        $string3 = /\stermux\-chroot\s.{0,100}\/cloudflared/ nocase ascii wide
                        $string4 = /\$Hc2\$w\$c\$rQW\$d\$s\$w\$b\$Hc2\$v\$xZp\$f\$w\$V9z\$rQW\$L\$U\$xZp/ nocase ascii wide
                        $string5 = /\$HOME\/\.tunneler/ nocase ascii wide
                        $string6 = /\$N0q\$x\$Hc2\$rQW/ nocase ascii wide
                        $string7 = /\$tunneler_dir\/loclx\.log/ nocase ascii wide
                        $string8 = /\.tunneler\/cf\.log/ nocase ascii wide
                        $string9 = /\.tunneler\/cloudflared/ nocase ascii wide
                        $string10 = /\.tunneler\/loclx/ nocase ascii wide
                        $string11 = /\.tunneler\/loclx\.log/ nocase ascii wide
                        $string12 = /\/\.localxpose\/\.access/
                        $string13 = /\/CamHacker\-.{0,100}\.png/ nocase ascii wide
                        $string14 = /\/CamHacker\.git/ nocase ascii wide
                        $string15 = /\/releases\/latest\/download\/cloudflared\-darwin\-amd64\.tgz/
                        $string16 = /\[CamHacker\]/ nocase ascii wide
                        $string17 = /\\CamHacker\\/ nocase ascii wide
                        $string18 = "=ogIXFlckIzYIRCekEHMORiIgwWY2VmCpICcahHJVRCTkcVUyRie5YFJ3RiZkAnW4RidkIzYIRiYkcHJzRCZkcVUyRyYkcHJyMGSkICIsFmdlhCJ9gnC" nocase ascii wide
                        $string19 = "CamHacker has a new update!" nocase ascii wide
                        $string20 = "CamHacker updated successfully" nocase ascii wide
                        $string21 = /CamHacker\/releases\/latest\/download\/websites\.zip/ nocase ascii wide
                        $string22 = "Cloudflared and Loclx have started successfully!" nocase ascii wide
                        $string23 = "Cloudflared has started successfully!" nocase ascii wide
                        $string24 = /Device\sarchitecture\sunknown\.\sDownload\scloudflared\/loclx\smanually/ nocase ascii wide
                        $string25 = "Don't_blindly_trust_obfuscated_code_it_might_do_something_bad" nocase ascii wide
                        $string26 = "Enter your loclx authtoken:" nocase ascii wide
                        $string27 = "Hey Dear! You Have Won Free Rs 399 Jio Recharge" nocase ascii wide
                        $string28 = /https\:\/\/api\.localxpose\.io\/api\/v2\/downloads\/loclx\-darwin\-amd64\.zip/
                        $string29 = "https://best-wishes-to-you" nocase ascii wide
                        $string30 = "https://free-399rs-jio-recharge" nocase ascii wide
                        $string31 = "https://join-zoom-online-meeting" nocase ascii wide
                        $string32 = /https\:\/\/raw\.githubusercontent\.com\/KasRoudra\/CamHacker/ nocase ascii wide
                        $string33 = "https://watch-youtube-videos-live" nocase ascii wide
                        $string34 = "KasRoudra/CamHacker" nocase ascii wide
                        $string35 = /kasroudrard\@gmail\.com/ nocase ascii wide
                        $string36 = "Starting php server at localhost:" nocase ascii wide
                        $string37 = "Tunneling failed! Start your own port forwarding/tunneling service at port " nocase ascii wide
                        $string38 = /unzip\swebsites\.zip\s\-d\ssites\s\>\s\/dev\/null/ nocase ascii wide
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