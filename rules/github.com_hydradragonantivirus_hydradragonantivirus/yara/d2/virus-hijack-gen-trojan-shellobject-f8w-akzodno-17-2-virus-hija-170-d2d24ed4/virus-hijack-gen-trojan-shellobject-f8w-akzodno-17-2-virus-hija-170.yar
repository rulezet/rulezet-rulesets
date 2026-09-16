import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_17_2_Virus_Hija_170 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_17_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_20_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_21_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_22_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_23_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_24_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_25_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cb6d5e61a70a952802f887e9ce37917e96f5eb5dac5fb2454f408f6a466d765"
    hash2       = "07cbaf0b0a7a6abfa094f2274442b79ad0d2592d1d6de540e219e4abf9a3fc31"
    hash3       = "65c222f2ecf26632067053df5e1d5152d8f517fc499172763972a6b8b07019aa"
    hash4       = "cfee2d1ae92f945be523ae3cf6d877dd3e28d5c5088e42b677d8b5fa964cd1f1"
    hash5       = "8deb585a0ced4febe7fa509dc615cbba9108e9676175109671281ce1fa082772"
    hash6       = "8c31804b3b511fc860f5ebcbce2b58db163cf35a64a0b1b24e6ed70241a02714"
    hash7       = "ea11f420144f85affedf067c4a06c09d4bca01f60951abe7e31286cbaeda12a1"

  strings:
    $s1  = "Command Bro !!!" fullword ascii
    $s2  = "Antivirus Startup.exe" fullword ascii
    $s3  = "Look @ \"C:\\Baca Bro !!!.txt\"" fullword ascii
    $s4  = "Program Files\\winamp\\winamp.exe" fullword ascii
    $s5  = "PROCESS EXP" fullword ascii
    $s6  = "command prompt" fullword ascii
    $s7  = "Nobron = Satria Dungu = Nothing !!!" fullword ascii
    $s8  = "Romdil = Tukang Jiplak = Nothing !!!" fullword ascii
    $s9  = "Nobron & Romdil -->> Kicked by The Amazing Brontok" fullword ascii
    $s10 = " /c net view /domain > \"" fullword ascii
    $s11 = "windows script" fullword ascii
    $s12 = "JowoBot #VM Community" fullword ascii
    $s13 = "#JowoBot-VM Community" fullword ascii
    $s14 = "computer management" fullword ascii
    $s15 = "net view /domain:" fullword ascii
    $s16 = "         Nobron = Satria Dungu = Nothing !!!" fullword ascii
    $s17 = "         Romdil = Tukang Jiplak = Nothing !!!" fullword ascii
    $s18 = "            Nobron & Romdil -->> Kicked by The Amazing Brontok" fullword ascii
    $s19 = "I want to share my photo with you." fullword ascii
    $s20 = "ASSOCIATE" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "1af1161d37f455fda94db97751b0224e" and (8 of them)
    ) or (all of them)
}