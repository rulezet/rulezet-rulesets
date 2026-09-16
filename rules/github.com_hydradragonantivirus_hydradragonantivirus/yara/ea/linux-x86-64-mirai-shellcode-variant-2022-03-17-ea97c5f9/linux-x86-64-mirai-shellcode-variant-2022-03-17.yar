rule Linux_x86_64_Mirai_shellcode_Variant_2022_03_17 {
  meta:
    description = "Detects new x86_64 Mirai variant"
    author      = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
    date        = "2022-03-17"
    hash1       = "220935a9c5f6de63ef0d7c63e6f9ba3033e962854ca1911e770de2578d3d7e35"

  strings:
    $mstr1 = "142.93.140.12:23" wide ascii
    $mstr2 = "[Shelling]-->[%s]-->[%s]-->[%s]-->[%s]-->[%s]" wide ascii
    $mstr3 = "been_there_done_that.3160" wide ascii
    $mstr4 = "Sending TCP Packets To: %s:%d for %d seconds" wide ascii
    $ppp1  = "/etc/apt/apt.conf" wide ascii
    $ppp2  = "/etc/yum.conf" wide ascii

  condition:
    uint16(0) == 0x457f and ((3 or all of ($mstr*)) and (all of ($ppp*)))
}