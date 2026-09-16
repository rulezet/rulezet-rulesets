import "pe"
rule quantum_ttsel {
  meta:
    description = "quantum - file ttsel.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
    date        = "2022-04-24"
    hash1       = "b6c11d4a4af4ad4919b1063184ee4fe86a5b4b2b50b53b4e9b9cc282a185afda"

  strings:
    $s1  = "DSUVWj ]" fullword ascii
    $s2  = "WWVh@]@" fullword ascii
    $s3  = "expand 32-byte k" fullword ascii  
    $s4  = "E4PSSh" fullword ascii  
    $s5  = "tySjD3" fullword ascii
    $s6  = "@]_^[Y" fullword ascii  
    $s7  = "0`0h0p0" fullword ascii  
    $s8  = "tV9_<tQf9_8tKSSh" fullword ascii
    $s9  = "Vj\\Yj?Xj:f" fullword ascii
    $s10 = "1-1:1I1T1Z1p1w1" fullword ascii
    $s11 = "8-999E9U9k9" fullword ascii
    $s12 = "8\"8)8H8i8t8" fullword ascii
    $s13 = "8\"868@8M8W8" fullword ascii
    $s14 = "3\"3)3>3F3f3m3t3}3" fullword ascii
    $s15 = "3\"3(3<3]3o3" fullword ascii
    $s16 = "9 9*909B9" fullword ascii
    $s17 = "9.979S9]9a9w9" fullword ascii
    $s18 = "txf9(tsf9)tnj\\P" fullword ascii
    $s19 = "5!5'5-5J5Y5b5i5~5" fullword ascii
    $s20 = "<2=7=>=E={=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and
    (pe.imphash() == "68b5e41a24d5a26c1c2196733789c238" or 8 of them)
}