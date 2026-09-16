rule Virus_Hijack_Backdoor_Hangup_B_288_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_288_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1828831743f26eb4ba29ea309196b927bf4a2c4817fb82d3be178d4b4b327ce8"

  strings:
    $s1  = "r3xfr9rrxufi69136if19ui75w3tq22twwYou may temporarily download the fonts to a printer or other output device to print content, a" ascii
    $s2  = "licensed use and one copy of each program media.jj7p3926801l826c1f6xll73i5i825f03l6f3i9r72ulo2ux56x46rf0xe9bt6h724hqnqk00w621nb6" ascii
    $s3  = "Multiple order entry line items may be entered as part of an individual customer order or quote and may also be automatically4x0" ascii
    $s4  = "obtain a license to allow for continued use, or if these alternatives are not commercially reasonable, the Provider may end the " ascii
    $s5  = "63f50oxu37u7olxcr3xfr9rrxufi69136if19ui75w3tq22twwannual report or the equivalent accounting or reporting document." fullword ascii
    $s6  = "the genuine Microsoft Certificate of Authenticity label with the accompanying genuine product key, and969kso4x15n745c97d5jlblr16" ascii
    $s7  = "the genuine Microsoft Certificate of Authenticity label with the accompanying genuine product key, and969kso4x15n745c97d5jlblr16" ascii
    $s8  = "n5lc98dnpv67ee66f0urqq2b7kgfw9dqdix51g92j857822cbvffrtx0n83136404rst0iugx56956s04vb1d62a50u0qx0mre7539iw28809k7123069eediddido4v" ascii
    $s9  = "may not use those programs and/or services ordered. You further agree that if you have used an Oracle Finance Division4m5go790sv" ascii
    $s10 = "may not use those programs and/or services ordered. You further agree that if you have used an Oracle Finance Division4m5go790sv" ascii
    $s11 = "37afmtoo6171wumx91h2509w5d3ok2s4bck7s809lu7fe8m77eig97kcp9another user simultaneously. As an exception, you may allow others to " ascii
    $s12 = "access the software" fullword ascii
    $s13 = "4vb1d62a50u0qx0mre7539iw28809k7123069eediddido4vhqa117eij347x432460g6kar8h0297x6e1414ke9x15k61wx473w9t7r1je2fmx71gace91a7i16ii4d" ascii
    $s14 = "licensed use and one copy of each program media.jj7p3926801l826c1f6xll73i5i825f03l6f3i9r72ulo2ux56x46rf0xe9bt6h724hqnqk00w621nb6" ascii
    $s15 = "This file helps us collect information about problems that you have while using the software. When375fecw35m1e0vg47s3mw92597lucj" ascii
    $s16 = "0urqq2b7kgfw9dqdix51g92j857822cbvffrtx0n83136404rst0iugx56956s04vb1d62a50u0qx0mre7539iw28809k7123069eediddido4vhqa117eij347x4324" ascii
    $s17 = " nonpayment or breach of Oracle" fullword ascii
    $s18 = "8m77eig97kcp9distribute copies of any media elements by themselves or as a product if the primary value of the product" fullword ascii
    $s19 = "1h2509w5d3ok2s4bck7s809lu7fe8m77eig97kcp9Field Technician: is defined as an engineer, technician, representative, or other perso" ascii
    $s20 = "Multiple order entry line items may be entered as part of an individual customer order or quote and may also be automatically4x0" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}