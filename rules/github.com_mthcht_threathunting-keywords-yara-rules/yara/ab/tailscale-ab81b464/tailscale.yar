rule tailscale
{
    meta:
        description = "Detection patterns for the tool 'tailscale' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tailscale"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " install tailscale" nocase ascii wide
                        $string2 = " net-vpn/tailscale" nocase ascii wide
                        $string3 = /\stailscale\.exe/ nocase ascii wide
                        $string4 = " tailscale-archive-keyring" nocase ascii wide
                        $string5 = /\.tailscale\-keyring\.list/ nocase ascii wide
                        $string6 = "/cmd/tailscaled" nocase ascii wide
                        $string7 = /\/sources\.list\.d\/tailscale\.list/ nocase ascii wide
                        $string8 = "/tailscale update"
                        $string9 = /\/tailscale\.exe/ nocase ascii wide
                        $string10 = "/tailscale/cli/"
                        $string11 = "/tailscale/client/" nocase ascii wide
                        $string12 = /\/tailscale\/clientupdate\/.{0,100}\.go/
                        $string13 = "/tailscale:unstable" nocase ascii wide
                        $string14 = /\/tailscale_.{0,100}_.{0,100}\.deb/ nocase ascii wide
                        $string15 = /\/tailscale_.{0,100}_.{0,100}\.tgz/ nocase ascii wide
                        $string16 = /\/tailscaled\.defaults/ nocase ascii wide
                        $string17 = /\/tailscaled\.go/ nocase ascii wide
                        $string18 = /\/tailscaled\.sock/ nocase ascii wide
                        $string19 = /\/tailscale\-setup\-.{0,100}\-.{0,100}\.msi/ nocase ascii wide
                        $string20 = /\/tailscale\-setup\-.{0,100}\.exe/ nocase ascii wide
                        $string21 = /\/test_tailscale\.sh/ nocase ascii wide
                        $string22 = /\\\\\.\\pipe\\tailscale\-test/ nocase ascii wide
                        $string23 = /\\cmd\\tailscaled/ nocase ascii wide
                        $string24 = /\\tailscale\.exe/ nocase ascii wide
                        $string25 = /\\tailscale\\cli\\/ nocase ascii wide
                        $string26 = /\\tailscale\\client\\/ nocase ascii wide
                        $string27 = /\\tailscale\\clientupdate\\/ nocase ascii wide
                        $string28 = /\\tailscale\\cmd\\/ nocase ascii wide
                        $string29 = /\\tailscale_.{0,100}_.{0,100}\.deb/ nocase ascii wide
                        $string30 = /\\tailscale_.{0,100}_.{0,100}\.tgz/ nocase ascii wide
                        $string31 = /\\tailscaled\.go/ nocase ascii wide
                        $string32 = /\\tailscale\-setup\-.{0,100}\.exe/ nocase ascii wide
                        $string33 = /\\test_tailscale\.sh/ nocase ascii wide
                        $string34 = "<h1>Hello from Tailscale</h1>" nocase ascii wide
                        $string35 = "apk add tailscale" nocase ascii wide
                        $string36 = "cmd/tailscale" nocase ascii wide
                        $string37 = "connected via tailscaled" nocase ascii wide
                        $string38 = "EnableTailscaleDNSSettings" nocase ascii wide
                        $string39 = "EnableTailscaleSubnets" nocase ascii wide
                        $string40 = /github\.com\/tailscale/ nocase ascii wide
                        $string41 = /http\:\/\/127\.0\.0\.1\:4000/ nocase ascii wide
                        $string42 = /http\:\/\/local\-tailscaled\.sock/ nocase ascii wide
                        $string43 = /https\:\/\/api\.tailscale\.com\/api\/v2\// nocase ascii wide
                        $string44 = /https\:\/\/apps\.apple\.com\/us\/app\/tailscale\/id/ nocase ascii wide
                        $string45 = /https\:\/\/login\.tailscale\.com\/admin\/settings\/keys/ nocase ascii wide
                        $string46 = /https\:\/\/tailscale\.com\/s\/resolvconf\-overwrite/ nocase ascii wide
                        $string47 = "install -y tailscale" nocase ascii wide
                        $string48 = /linuxfw\.TailscaleSubnetRouteMark/
                        $string49 = /local\-tailscaled\.sock/ nocase ascii wide
                        $string50 = /login\.tailscale\.com/ nocase ascii wide
                        $string51 = "pacman -S tailscale" nocase ascii wide
                        $string52 = /pkgctl\-Tailscale\.service/ nocase ascii wide
                        $string53 = /pkgs\.tailscale\.com\/.{0,100}\// nocase ascii wide
                        $string54 = "rc-update add tailscale" nocase ascii wide
                        $string55 = /resolv\.pre\-tailscale\-backup\.conf/ nocase ascii wide
                        $string56 = /resolv\.tailscale\.conf/ nocase ascii wide
                        $string57 = "service tailscaled " nocase ascii wide
                        $string58 = "Serving Tailscale web client on http://" nocase ascii wide
                        $string59 = "Starting tailscaled" nocase ascii wide
                        $string60 = "sudo tailscale up"
                        $string61 = "systemctl enable --now tailscaled" nocase ascii wide
                        $string62 = "tailscale ip -4" nocase ascii wide
                        $string63 = "Tailscale is not running" nocase ascii wide
                        $string64 = "tailscale ping -" nocase ascii wide
                        $string65 = "tailscale serve -" nocase ascii wide
                        $string66 = "tailscale set --auto-update" nocase ascii wide
                        $string67 = "Tailscale SSH is " nocase ascii wide
                        $string68 = "tailscale up --login-server=" nocase ascii wide
                        $string69 = "Tailscale was already stopped" nocase ascii wide
                        $string70 = /tailscale\.com\/install\.sh/ nocase ascii wide
                        $string71 = /tailscale\.com\/logger\.Logf/ nocase ascii wide
                        $string72 = /tailscale\.exe\s/ nocase ascii wide
                        $string73 = "tailscale/go/releases/download/" nocase ascii wide
                        $string74 = "tailscale/net/dns/" nocase ascii wide
                        $string75 = /tailscale\/tailscale\.go/ nocase ascii wide
                        $string76 = /tailscale\\net\\dns/ nocase ascii wide
                        $string77 = /tailscale\\scripts\\installer\.sh/ nocase ascii wide
                        $string78 = /tailscale\\tailscale\.go/ nocase ascii wide
                        $string79 = "Tailscaled exited" nocase ascii wide
                        $string80 = /tailscaled\.exe/ nocase ascii wide
                        $string81 = /tailscaled\.log/ nocase ascii wide
                        $string82 = /tailscaled\.openrc/ nocase ascii wide
                        $string83 = /tailscaled\.sh/ nocase ascii wide
                        $string84 = /tailscaled\.stdout\.log/ nocase ascii wide
                        $string85 = /tailscaled_notwindows\.go/ nocase ascii wide
                        $string86 = /tailscale\-ipn\.exe/ nocase ascii wide
                        $string87 = /tailscale\-ipn\.log\.conf/ nocase ascii wide
                        $string88 = /tailscale\-setup\-.{0,100}\.exe\s/ nocase ascii wide
                        $string89 = /tailscale\-setup\-full\-.{0,100}\.exe/ nocase ascii wide
                        $string90 = "Updating Tailscale from " nocase ascii wide
                        $string91 = /yum\.repos\.d\/tailscale\.repo/ nocase ascii wide
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