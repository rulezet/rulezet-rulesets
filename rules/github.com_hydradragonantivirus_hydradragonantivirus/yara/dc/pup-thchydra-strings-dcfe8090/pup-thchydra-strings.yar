rule PUP_THCHydra_strings {
    meta:
        description = "Matches strings found in the THC-Hydra network scanner."
        last_modified = "2024-02-24"
        author = "@petermstewart"
        DaysofYara = "55/100"
        ref = "https://github.com/vanhauser-thc/thc-hydra"
        ref = "https://github.com/maaaaz/thc-hydra-windows"

    strings:
        $a1 = "hydra -P pass.txt target cisco-enable  (direct console access)"
        $a2 = "hydra -P pass.txt -m cisco target cisco-enable  (Logon password cisco)"
        $a3 = "hydra -l foo -m bar -P pass.txt target cisco-enable  (AAA Login foo, password bar)"
        $a4 = "hydra -L urllist.txt -s 3128 target.com http-proxy-urlenum user:pass"
        $a5 = "hydra -L urllist.txt http-proxy-urlenum://target.com:3128/user:pass"
        $a6 = "USER hydra%d hydra %s :hydra"
        $a7 = "hydra rdp://192.168.0.1/firstdomainname -l john -p doe"
        $a8 = "User-Agent: Mozilla/4.0 (Hydra)"

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
        all of them
}