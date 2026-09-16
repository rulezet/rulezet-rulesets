import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_17_1_Virus_Hijac_250 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f4e08ff55f9130c843fb3251856a8bbf945f615050a51fdc667ca113fb2e867"
    hash2       = "ad83f4a4563b94420182654f956f45c6555d88c4fb0392dbe73df0eeafbdfc17"

  strings:
    $s1  = "Warning: You have selected to clear Windows updates from your system. You will not be able to uninstall these updates after this" wide
    $s2  = "Scans core Operating System files for version consistency and repairs any issues found." fullword wide
    $s3  = "Unable to locate GPResult.exe" fullword wide
    $s4  = "Runs the Deployment Imaging Service Manager to restore health on all Windows Operating System files" fullword wide
    $s5  = "System Temp Size:" fullword wide
    $s6  = "Null Target" fullword wide
    $s7  = "Error validating downloaded file. SHA256 checksum mismatch." fullword wide
    $s8  = "Failed to get update" fullword wide
    $s9  = " available. Download now?" fullword wide
    $s10 = "Download available" fullword wide
    $s11 = "/Q     Runs commands then exits." fullword wide
    $s12 = "Get Drive Statistics" fullword wide
    $s13 = "Save output to log" fullword wide
    $s14 = "Clear log window" fullword wide
    $s15 = "Failed to mount disk image" fullword wide
    $s16 = "Mount failure" fullword wide
    $s17 = "Reformat destination with a file system that accepts larger files." fullword wide
    $s18 = "File size error" fullword wide
    $s19 = "Error copying " fullword wide
    $s20 = "Unauthorized Access Exception" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}