rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_a4YD_Xe_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26765ed902db06f8c02348812a95806700d46b42a2147bf0ff6e43b0c0e109a5"

  strings:
    $s1  = "nibh ipsum consequat nisl vel pretium. Vel eros donec ac odio tempor" fullword ascii
    $s2  = "?leo urna. Lobortis feugiat vivamus at augue eget arcu. Feugiat pretium" fullword ascii
    $s3  = "orci. Ipsum dolor sit amet consectetur adipiscing elit. Massa placerat" fullword ascii
    $s4  = "sit amet est placerat in egestas erat. Dignissim convallis aenean et tortor" fullword ascii
    $s5  = "placerat duis ultricies lacus. Ultrices eros in cursus turpis massa" fullword ascii
    $s6  = "      Tortor posuere ac ut consequat. Vel eros donec ac odio tempor orci " fullword ascii
    $s7  = "    at risus. Non nisi est sit amet facilisis magna etiam tempor. Massa" fullword ascii
    $s8  = "title ftghjtfydyrtrtrrrtrrtrtr" fullword ascii
    $s9  = " (2):fghfghcvfghf(next)" fullword ascii
    $s10 = "   (3)ultricies lacus. Interdum velit euismod in pellentesque massa placerat " fullword ascii
    $s11 = "    tincidunt lobortis feugiat vivamus at augue eget. Dictum varius duis at " fullword ascii
    $s12 = " (4):dfgdfgdfhthtfh(next)" fullword ascii
    $s13 = "   (2)donec. Interdum velit euismod in pellentesque massa placerat duis " fullword ascii
    $s14 = "mode con cols=55 lines=30" fullword ascii
    $s15 = "Nullam vehicula ipsum a arcu cursus. Pharetra convallis posuere morbi" fullword ascii
    $s16 = "   (1)nam libero justo laoreet sit amet. Condimentum lacinia quis vel eros" fullword ascii
    $s17 = "   (4)duis ultricies. Congue quisque egestas diam in arcu cursus euismod. " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}