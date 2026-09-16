rule wstunnel
{
    meta:
        description = "Detection patterns for the tool 'wstunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wstunnel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sclient\s\-\-http\-upgrade\-path\-prefix\s.{0,1000}wss/ nocase ascii wide
                        $string2 = " client -L socks5://" nocase ascii wide
                        $string3 = /\sclient\s\-L\sstdio\:\/\/.{0,1000}\sws\:\// nocase ascii wide
                        $string4 = /\sclient\s\-L\stcp\:\/\/.{0,1000}\swss\:\/\// nocase ascii wide
                        $string5 = /\sclient\s\-L\s\'tproxy\+tcp\:\/\/.{0,1000}\s\-L\s\'tproxy\+udp\:\/\// nocase ascii wide
                        $string6 = /\sclient\s\-L\s\'udp\:\/\/.{0,1000}\swss\:\/\// nocase ascii wide
                        $string7 = /\sclient\s\-R\s\'tcp\:\/\/\[\:\:\]\:/ nocase ascii wide
                        $string8 = /\s\-\-connection\-min\-idle\s.{0,1000}\sws\:\/\// nocase ascii wide
                        $string9 = " --local-to-remote socks5://" nocase ascii wide
                        $string10 = " --local-to-remote stdio://" nocase ascii wide
                        $string11 = " --local-to-remote tcp://" nocase ascii wide
                        $string12 = /\s\-\-local\-to\-remote\stproxy\+tcp\:\/\// nocase ascii wide
                        $string13 = /\s\-\-local\-to\-remote\stproxy\+udp\:\/\// nocase ascii wide
                        $string14 = " --local-to-remote udp://" nocase ascii wide
                        $string15 = " --remote-to-local socks://" nocase ascii wide
                        $string16 = " --remote-to-local tcp://" nocase ascii wide
                        $string17 = " --remote-to-local udp://" nocase ascii wide
                        $string18 = /\s\-\-restrict\-to\slocalhost\:.{0,1000}\swss\:\/\// nocase ascii wide
                        $string19 = /\sserver\s\-\-restrict\-http\-upgrade\-path\-prefix\s.{0,1000}wss/ nocase ascii wide
                        $string20 = /\sserver\swss\:\/\/\[\:\:\]\:/ nocase ascii wide
                        $string21 = /\sws\:\/\/\[\:\:\]\:/ nocase ascii wide
                        $string22 = /\swss\:\/\/0\.0\.0\.0\:/ nocase ascii wide
                        $string23 = /\swstunnel\.exe/ nocase ascii wide
                        $string24 = "/home/app/wstunnel"
                        $string25 = "/wstunnel wstunnel"
                        $string26 = /\/wstunnel\.exe/ nocase ascii wide
                        $string27 = /\/wstunnel\.git/ nocase ascii wide
                        $string28 = "/wstunnel/certs/"
                        $string29 = "/wstunnel:latest" nocase ascii wide
                        $string30 = /\:\/\/wstunnel\.server\.com/ nocase ascii wide
                        $string31 = /\\wstunnel\.exe/ nocase ascii wide
                        $string32 = /\\wstunnel\\certs\\/ nocase ascii wide
                        $string33 = "2ab5af4a7fa7d14b4a4facef9b4d80bd3ada7e20c36712ece61ce9c294107745" nocase ascii wide
                        $string34 = "4e6e01948bbd969f58b1535f30efc9b75c63e0d362b9487b9ea8ebe768ce893e" nocase ascii wide
                        $string35 = "7a51ed902fc804066c4617af21d0325cceebce588ca66709c697916ce5214e64" nocase ascii wide
                        $string36 = "7cda14dc04bb731f09880db6310c9d9d4ee96176931627f322ec725cde6bd18b" nocase ascii wide
                        $string37 = "9ad6daccfd1d3d349a93950f599eed59280268431d76bad7fc624d4cd4c565a5" nocase ascii wide
                        $string38 = "Cannot start wstunnel server:" nocase ascii wide
                        $string39 = /curl\s\-x\ssocks5h\:\/\/127\.0\.0\.1\:/ nocase ascii wide
                        $string40 = "erebe/wstunnel" nocase ascii wide
                        $string41 = "f7267a8880e45961219a6204a3a8ae5fff31e495f3f930e487f80cf89850f16f" nocase ascii wide
                        $string42 = "h3GywpDrP6gJEdZ6xbJbZZVFmvFZDCa4KcRd" nocase ascii wide
                        $string43 = "ssh -o ProxyCommand=\"wstunnel" nocase ascii wide
                        $string44 = "Starting wstunnel server v" nocase ascii wide
                        $string45 = "target/debug/wstunnel" nocase ascii wide
                        $string46 = "wstunnel client " nocase ascii wide
                        $string47 = "wstunnel server " nocase ascii wide
                        $string48 = /wstunnel.{0,1000}\s\-\-restrict\-to\s127\.0\.0\.1\:22/ nocase ascii wide
                        $string49 = /wstunnel.{0,1000}cert\.pem/ nocase ascii wide
                        $string50 = /wstunnel.{0,1000}key\.pem/ nocase ascii wide
                        $string51 = /wstunnel\.exe\s/ nocase ascii wide
                        $string52 = "wstunnel/pkgs/container/wstunnel" nocase ascii wide
                        $string53 = /wstunnel_.{0,1000}_darwin_amd64\.tar\.gz/
                        $string54 = /wstunnel_.{0,1000}_linux_amd64\.tar\.gz/
                        $string55 = /wstunnel_.{0,1000}_linux_arm64\.tar\.gz/
                        $string56 = /wstunnel_.{0,1000}_linux_armv7\.tar\.gz/
                        $string57 = /wstunnel_.{0,1000}_windows_386\.tar\.gz/ nocase ascii wide
                        $string58 = /wstunnel_.{0,1000}_windows_amd64\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}