rule rule_wstunnel_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wstunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wstunnel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wstunnel_offensive_tool_keyword = /\sclient\s\-\-http\-upgrade\-path\-prefix\s.{0,1000}wss/ nocase ascii wide
                        $string2_wstunnel_offensive_tool_keyword = " client -L socks5://" nocase ascii wide
                        $string3_wstunnel_offensive_tool_keyword = /\sclient\s\-L\sstdio\:\/\/.{0,1000}\sws\:\// nocase ascii wide
                        $string4_wstunnel_offensive_tool_keyword = /\sclient\s\-L\stcp\:\/\/.{0,1000}\swss\:\/\// nocase ascii wide
                        $string5_wstunnel_offensive_tool_keyword = /\sclient\s\-L\s\'tproxy\+tcp\:\/\/.{0,1000}\s\-L\s\'tproxy\+udp\:\/\// nocase ascii wide
                        $string6_wstunnel_offensive_tool_keyword = /\sclient\s\-L\s\'udp\:\/\/.{0,1000}\swss\:\/\// nocase ascii wide
                        $string7_wstunnel_offensive_tool_keyword = /\sclient\s\-R\s\'tcp\:\/\/\[\:\:\]\:/ nocase ascii wide
                        $string8_wstunnel_offensive_tool_keyword = /\s\-\-connection\-min\-idle\s.{0,1000}\sws\:\/\// nocase ascii wide
                        $string9_wstunnel_offensive_tool_keyword = " --local-to-remote socks5://" nocase ascii wide
                        $string10_wstunnel_offensive_tool_keyword = " --local-to-remote stdio://" nocase ascii wide
                        $string11_wstunnel_offensive_tool_keyword = " --local-to-remote tcp://" nocase ascii wide
                        $string12_wstunnel_offensive_tool_keyword = /\s\-\-local\-to\-remote\stproxy\+tcp\:\/\// nocase ascii wide
                        $string13_wstunnel_offensive_tool_keyword = /\s\-\-local\-to\-remote\stproxy\+udp\:\/\// nocase ascii wide
                        $string14_wstunnel_offensive_tool_keyword = " --local-to-remote udp://" nocase ascii wide
                        $string15_wstunnel_offensive_tool_keyword = " --remote-to-local socks://" nocase ascii wide
                        $string16_wstunnel_offensive_tool_keyword = " --remote-to-local tcp://" nocase ascii wide
                        $string17_wstunnel_offensive_tool_keyword = " --remote-to-local udp://" nocase ascii wide
                        $string18_wstunnel_offensive_tool_keyword = /\s\-\-restrict\-to\slocalhost\:.{0,1000}\swss\:\/\// nocase ascii wide
                        $string19_wstunnel_offensive_tool_keyword = /\sserver\s\-\-restrict\-http\-upgrade\-path\-prefix\s.{0,1000}wss/ nocase ascii wide
                        $string20_wstunnel_offensive_tool_keyword = /\sserver\swss\:\/\/\[\:\:\]\:/ nocase ascii wide
                        $string21_wstunnel_offensive_tool_keyword = /\sws\:\/\/\[\:\:\]\:/ nocase ascii wide
                        $string22_wstunnel_offensive_tool_keyword = /\swss\:\/\/0\.0\.0\.0\:/ nocase ascii wide
                        $string23_wstunnel_offensive_tool_keyword = /\swstunnel\.exe/ nocase ascii wide
                        $string24_wstunnel_offensive_tool_keyword = "/home/app/wstunnel"
                        $string25_wstunnel_offensive_tool_keyword = "/wstunnel wstunnel"
                        $string26_wstunnel_offensive_tool_keyword = /\/wstunnel\.exe/ nocase ascii wide
                        $string27_wstunnel_offensive_tool_keyword = /\/wstunnel\.git/ nocase ascii wide
                        $string28_wstunnel_offensive_tool_keyword = "/wstunnel/certs/"
                        $string29_wstunnel_offensive_tool_keyword = "/wstunnel:latest" nocase ascii wide
                        $string30_wstunnel_offensive_tool_keyword = /\:\/\/wstunnel\.server\.com/ nocase ascii wide
                        $string31_wstunnel_offensive_tool_keyword = /\\wstunnel\.exe/ nocase ascii wide
                        $string32_wstunnel_offensive_tool_keyword = /\\wstunnel\\certs\\/ nocase ascii wide
                        $string33_wstunnel_offensive_tool_keyword = "2ab5af4a7fa7d14b4a4facef9b4d80bd3ada7e20c36712ece61ce9c294107745" nocase ascii wide
                        $string34_wstunnel_offensive_tool_keyword = "4e6e01948bbd969f58b1535f30efc9b75c63e0d362b9487b9ea8ebe768ce893e" nocase ascii wide
                        $string35_wstunnel_offensive_tool_keyword = "7a51ed902fc804066c4617af21d0325cceebce588ca66709c697916ce5214e64" nocase ascii wide
                        $string36_wstunnel_offensive_tool_keyword = "7cda14dc04bb731f09880db6310c9d9d4ee96176931627f322ec725cde6bd18b" nocase ascii wide
                        $string37_wstunnel_offensive_tool_keyword = "9ad6daccfd1d3d349a93950f599eed59280268431d76bad7fc624d4cd4c565a5" nocase ascii wide
                        $string38_wstunnel_offensive_tool_keyword = "Cannot start wstunnel server:" nocase ascii wide
                        $string39_wstunnel_offensive_tool_keyword = /curl\s\-x\ssocks5h\:\/\/127\.0\.0\.1\:/ nocase ascii wide
                        $string40_wstunnel_offensive_tool_keyword = "erebe/wstunnel" nocase ascii wide
                        $string41_wstunnel_offensive_tool_keyword = "f7267a8880e45961219a6204a3a8ae5fff31e495f3f930e487f80cf89850f16f" nocase ascii wide
                        $string42_wstunnel_offensive_tool_keyword = "h3GywpDrP6gJEdZ6xbJbZZVFmvFZDCa4KcRd" nocase ascii wide
                        $string43_wstunnel_offensive_tool_keyword = "ssh -o ProxyCommand=\"wstunnel" nocase ascii wide
                        $string44_wstunnel_offensive_tool_keyword = "Starting wstunnel server v" nocase ascii wide
                        $string45_wstunnel_offensive_tool_keyword = "target/debug/wstunnel" nocase ascii wide
                        $string46_wstunnel_offensive_tool_keyword = "wstunnel client " nocase ascii wide
                        $string47_wstunnel_offensive_tool_keyword = "wstunnel server " nocase ascii wide
                        $string48_wstunnel_offensive_tool_keyword = /wstunnel.{0,1000}\s\-\-restrict\-to\s127\.0\.0\.1\:22/ nocase ascii wide
                        $string49_wstunnel_offensive_tool_keyword = /wstunnel.{0,1000}cert\.pem/ nocase ascii wide
                        $string50_wstunnel_offensive_tool_keyword = /wstunnel.{0,1000}key\.pem/ nocase ascii wide
                        $string51_wstunnel_offensive_tool_keyword = /wstunnel\.exe\s/ nocase ascii wide
                        $string52_wstunnel_offensive_tool_keyword = "wstunnel/pkgs/container/wstunnel" nocase ascii wide
                        $string53_wstunnel_offensive_tool_keyword = /wstunnel_.{0,1000}_darwin_amd64\.tar\.gz/
                        $string54_wstunnel_offensive_tool_keyword = /wstunnel_.{0,1000}_linux_amd64\.tar\.gz/
                        $string55_wstunnel_offensive_tool_keyword = /wstunnel_.{0,1000}_linux_arm64\.tar\.gz/
                        $string56_wstunnel_offensive_tool_keyword = /wstunnel_.{0,1000}_linux_armv7\.tar\.gz/
                        $string57_wstunnel_offensive_tool_keyword = /wstunnel_.{0,1000}_windows_386\.tar\.gz/ nocase ascii wide
                        $string58_wstunnel_offensive_tool_keyword = /wstunnel_.{0,1000}_windows_amd64\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}