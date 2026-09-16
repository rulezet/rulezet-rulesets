rule rule_tailscale_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tailscale' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tailscale"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tailscale_greyware_tool_keyword = " install tailscale" nocase ascii wide
                        $string2_tailscale_greyware_tool_keyword = " net-vpn/tailscale" nocase ascii wide
                        $string3_tailscale_greyware_tool_keyword = /\stailscale\.exe/ nocase ascii wide
                        $string4_tailscale_greyware_tool_keyword = " tailscale-archive-keyring" nocase ascii wide
                        $string5_tailscale_greyware_tool_keyword = /\.tailscale\-keyring\.list/ nocase ascii wide
                        $string6_tailscale_greyware_tool_keyword = "/cmd/tailscaled" nocase ascii wide
                        $string7_tailscale_greyware_tool_keyword = /\/sources\.list\.d\/tailscale\.list/ nocase ascii wide
                        $string8_tailscale_greyware_tool_keyword = "/tailscale update"
                        $string9_tailscale_greyware_tool_keyword = /\/tailscale\.exe/ nocase ascii wide
                        $string10_tailscale_greyware_tool_keyword = "/tailscale/cli/"
                        $string11_tailscale_greyware_tool_keyword = "/tailscale/client/" nocase ascii wide
                        $string12_tailscale_greyware_tool_keyword = /\/tailscale\/clientupdate\/.{0,1000}\.go/
                        $string13_tailscale_greyware_tool_keyword = "/tailscale:unstable" nocase ascii wide
                        $string14_tailscale_greyware_tool_keyword = /\/tailscale_.{0,1000}_.{0,1000}\.deb/ nocase ascii wide
                        $string15_tailscale_greyware_tool_keyword = /\/tailscale_.{0,1000}_.{0,1000}\.tgz/ nocase ascii wide
                        $string16_tailscale_greyware_tool_keyword = /\/tailscaled\.defaults/ nocase ascii wide
                        $string17_tailscale_greyware_tool_keyword = /\/tailscaled\.go/ nocase ascii wide
                        $string18_tailscale_greyware_tool_keyword = /\/tailscaled\.sock/ nocase ascii wide
                        $string19_tailscale_greyware_tool_keyword = /\/tailscale\-setup\-.{0,1000}\-.{0,1000}\.msi/ nocase ascii wide
                        $string20_tailscale_greyware_tool_keyword = /\/tailscale\-setup\-.{0,1000}\.exe/ nocase ascii wide
                        $string21_tailscale_greyware_tool_keyword = /\/test_tailscale\.sh/ nocase ascii wide
                        $string22_tailscale_greyware_tool_keyword = /\\\\\.\\pipe\\tailscale\-test/ nocase ascii wide
                        $string23_tailscale_greyware_tool_keyword = /\\cmd\\tailscaled/ nocase ascii wide
                        $string24_tailscale_greyware_tool_keyword = /\\tailscale\.exe/ nocase ascii wide
                        $string25_tailscale_greyware_tool_keyword = /\\tailscale\\cli\\/ nocase ascii wide
                        $string26_tailscale_greyware_tool_keyword = /\\tailscale\\client\\/ nocase ascii wide
                        $string27_tailscale_greyware_tool_keyword = /\\tailscale\\clientupdate\\/ nocase ascii wide
                        $string28_tailscale_greyware_tool_keyword = /\\tailscale\\cmd\\/ nocase ascii wide
                        $string29_tailscale_greyware_tool_keyword = /\\tailscale_.{0,1000}_.{0,1000}\.deb/ nocase ascii wide
                        $string30_tailscale_greyware_tool_keyword = /\\tailscale_.{0,1000}_.{0,1000}\.tgz/ nocase ascii wide
                        $string31_tailscale_greyware_tool_keyword = /\\tailscaled\.go/ nocase ascii wide
                        $string32_tailscale_greyware_tool_keyword = /\\tailscale\-setup\-.{0,1000}\.exe/ nocase ascii wide
                        $string33_tailscale_greyware_tool_keyword = /\\test_tailscale\.sh/ nocase ascii wide
                        $string34_tailscale_greyware_tool_keyword = "<h1>Hello from Tailscale</h1>" nocase ascii wide
                        $string35_tailscale_greyware_tool_keyword = "apk add tailscale" nocase ascii wide
                        $string36_tailscale_greyware_tool_keyword = "cmd/tailscale" nocase ascii wide
                        $string37_tailscale_greyware_tool_keyword = "connected via tailscaled" nocase ascii wide
                        $string38_tailscale_greyware_tool_keyword = "EnableTailscaleDNSSettings" nocase ascii wide
                        $string39_tailscale_greyware_tool_keyword = "EnableTailscaleSubnets" nocase ascii wide
                        $string40_tailscale_greyware_tool_keyword = /github\.com\/tailscale/ nocase ascii wide
                        $string41_tailscale_greyware_tool_keyword = /http\:\/\/127\.0\.0\.1\:4000/ nocase ascii wide
                        $string42_tailscale_greyware_tool_keyword = /http\:\/\/local\-tailscaled\.sock/ nocase ascii wide
                        $string43_tailscale_greyware_tool_keyword = /https\:\/\/api\.tailscale\.com\/api\/v2\// nocase ascii wide
                        $string44_tailscale_greyware_tool_keyword = /https\:\/\/apps\.apple\.com\/us\/app\/tailscale\/id/ nocase ascii wide
                        $string45_tailscale_greyware_tool_keyword = /https\:\/\/login\.tailscale\.com\/admin\/settings\/keys/ nocase ascii wide
                        $string46_tailscale_greyware_tool_keyword = /https\:\/\/tailscale\.com\/s\/resolvconf\-overwrite/ nocase ascii wide
                        $string47_tailscale_greyware_tool_keyword = "install -y tailscale" nocase ascii wide
                        $string48_tailscale_greyware_tool_keyword = /linuxfw\.TailscaleSubnetRouteMark/
                        $string49_tailscale_greyware_tool_keyword = /local\-tailscaled\.sock/ nocase ascii wide
                        $string50_tailscale_greyware_tool_keyword = /login\.tailscale\.com/ nocase ascii wide
                        $string51_tailscale_greyware_tool_keyword = "pacman -S tailscale" nocase ascii wide
                        $string52_tailscale_greyware_tool_keyword = /pkgctl\-Tailscale\.service/ nocase ascii wide
                        $string53_tailscale_greyware_tool_keyword = /pkgs\.tailscale\.com\/.{0,1000}\// nocase ascii wide
                        $string54_tailscale_greyware_tool_keyword = "rc-update add tailscale" nocase ascii wide
                        $string55_tailscale_greyware_tool_keyword = /resolv\.pre\-tailscale\-backup\.conf/ nocase ascii wide
                        $string56_tailscale_greyware_tool_keyword = /resolv\.tailscale\.conf/ nocase ascii wide
                        $string57_tailscale_greyware_tool_keyword = "service tailscaled " nocase ascii wide
                        $string58_tailscale_greyware_tool_keyword = "Serving Tailscale web client on http://" nocase ascii wide
                        $string59_tailscale_greyware_tool_keyword = "Starting tailscaled" nocase ascii wide
                        $string60_tailscale_greyware_tool_keyword = "sudo tailscale up"
                        $string61_tailscale_greyware_tool_keyword = "systemctl enable --now tailscaled" nocase ascii wide
                        $string62_tailscale_greyware_tool_keyword = "tailscale ip -4" nocase ascii wide
                        $string63_tailscale_greyware_tool_keyword = "Tailscale is not running" nocase ascii wide
                        $string64_tailscale_greyware_tool_keyword = "tailscale ping -" nocase ascii wide
                        $string65_tailscale_greyware_tool_keyword = "tailscale serve -" nocase ascii wide
                        $string66_tailscale_greyware_tool_keyword = "tailscale set --auto-update" nocase ascii wide
                        $string67_tailscale_greyware_tool_keyword = "Tailscale SSH is " nocase ascii wide
                        $string68_tailscale_greyware_tool_keyword = "tailscale up --login-server=" nocase ascii wide
                        $string69_tailscale_greyware_tool_keyword = "Tailscale was already stopped" nocase ascii wide
                        $string70_tailscale_greyware_tool_keyword = /tailscale\.com\/install\.sh/ nocase ascii wide
                        $string71_tailscale_greyware_tool_keyword = /tailscale\.com\/logger\.Logf/ nocase ascii wide
                        $string72_tailscale_greyware_tool_keyword = /tailscale\.exe\s/ nocase ascii wide
                        $string73_tailscale_greyware_tool_keyword = "tailscale/go/releases/download/" nocase ascii wide
                        $string74_tailscale_greyware_tool_keyword = "tailscale/net/dns/" nocase ascii wide
                        $string75_tailscale_greyware_tool_keyword = /tailscale\/tailscale\.go/ nocase ascii wide
                        $string76_tailscale_greyware_tool_keyword = /tailscale\\net\\dns/ nocase ascii wide
                        $string77_tailscale_greyware_tool_keyword = /tailscale\\scripts\\installer\.sh/ nocase ascii wide
                        $string78_tailscale_greyware_tool_keyword = /tailscale\\tailscale\.go/ nocase ascii wide
                        $string79_tailscale_greyware_tool_keyword = "Tailscaled exited" nocase ascii wide
                        $string80_tailscale_greyware_tool_keyword = /tailscaled\.exe/ nocase ascii wide
                        $string81_tailscale_greyware_tool_keyword = /tailscaled\.log/ nocase ascii wide
                        $string82_tailscale_greyware_tool_keyword = /tailscaled\.openrc/ nocase ascii wide
                        $string83_tailscale_greyware_tool_keyword = /tailscaled\.sh/ nocase ascii wide
                        $string84_tailscale_greyware_tool_keyword = /tailscaled\.stdout\.log/ nocase ascii wide
                        $string85_tailscale_greyware_tool_keyword = /tailscaled_notwindows\.go/ nocase ascii wide
                        $string86_tailscale_greyware_tool_keyword = /tailscale\-ipn\.exe/ nocase ascii wide
                        $string87_tailscale_greyware_tool_keyword = /tailscale\-ipn\.log\.conf/ nocase ascii wide
                        $string88_tailscale_greyware_tool_keyword = /tailscale\-setup\-.{0,1000}\.exe\s/ nocase ascii wide
                        $string89_tailscale_greyware_tool_keyword = /tailscale\-setup\-full\-.{0,1000}\.exe/ nocase ascii wide
                        $string90_tailscale_greyware_tool_keyword = "Updating Tailscale from " nocase ascii wide
                        $string91_tailscale_greyware_tool_keyword = /yum\.repos\.d\/tailscale\.repo/ nocase ascii wide

    condition:
        any of them
}