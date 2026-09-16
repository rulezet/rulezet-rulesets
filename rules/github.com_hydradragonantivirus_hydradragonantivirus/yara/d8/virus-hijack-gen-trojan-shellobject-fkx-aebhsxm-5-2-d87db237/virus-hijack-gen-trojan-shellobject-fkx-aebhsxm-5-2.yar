rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4f771eec7a852ae96dfccd4796e9930143891c7726fb33b6d1611bf0f9e735e"

  strings:
    $x1  = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2  = "  <!-- Indicate JDK is high-dpi aware. -->" fullword ascii
    $s3  = "GAttempt to add quarantined event to quarantine." fullword wide
    $s4  = "Java(TM) Web Start 10.45.2.18-fcs" fullword wide
    $s5  = "'Get' failed because the Variant is not the correct type." fullword ascii
    $s6  = "lication></compatibility><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schem" ascii
    $s7  = " is being used after it has been destroyed." fullword ascii
    $s8  = "GEvent Buffer is full" fullword wide
    $s9  = "G!!UNAVAILABLE!!" fullword wide
    $s10 = "Variant type ID is invalid.  This is probably because the variant object is being used without being properly initialized, or it" ascii
    $s11 = "Variant type ID is invalid.  This is probably because the variant object is being used without being properly initialized, or it" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}