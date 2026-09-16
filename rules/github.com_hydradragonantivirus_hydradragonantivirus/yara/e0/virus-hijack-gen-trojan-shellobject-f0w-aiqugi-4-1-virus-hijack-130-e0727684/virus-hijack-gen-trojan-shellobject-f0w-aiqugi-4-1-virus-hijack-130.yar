import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_4_1_Virus_Hijack_130 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aSlVvue_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3112ee48980ee355e436b9f1f525b69c09d522fd26edd28acb64066bd24a57a0"
    hash2       = "660abb9fe016d15a4064be6ed8a9c3dddb3ae71c06d80f8b5e32d0c471fc1dc3"
    hash3       = "0020b5f10333813bb3ba921bf702cd6ec4f9f7631c53e948ca0710d14cd55e34"

  strings:
    $x1  = "  = Process: C:\\Windows\\SysWOW64\\wusa.exe" fullword ascii
    $s2  = "  = Module: C:\\Windows\\SysWOW64\\wuapi.dll" fullword ascii
    $s3  = "Installing self-contained with source=C:\\Windows\\SoftwareDistribution\\Download\\fbffd999691b70a044083664d2fb7c25\\Windows6.1-" ascii
    $s4  = "Installing self-contained with source=C:\\Windows\\SoftwareDistribution\\Download\\fbffd999691b70a044083664d2fb7c25\\Windows6.1-" ascii
    $s5  = "  - Added scan package service, ServiceID = {5D2C4541-99AC-4C50-917F-B6FE22C2A61B} Third party service" fullword ascii
    $s6  = "  - Added scan package service, ServiceID = {2B4E3C91-AC39-462D-9FFA-B65B57FF5A9D} Third party service" fullword ascii
    $s7  = "  - Added scan package service, ServiceID = {A249CF70-4A46-4DA4-B8E3-9276E3C7C856} Third party service" fullword ascii
    $s8  = "Validating signature for C:\\Windows\\SoftwareDistribution\\Download\\fbffd999691b70a044083664d2fb7c25_ctc\\Windows6.1-KB2999226" ascii
    $s9  = "  - Added scan package service, ServiceID = {9D085694-7E0B-4598-B6C9-47D08F306A11} Third party service" fullword ascii
    $s10 = "  - ServiceID = {2B4E3C91-AC39-462D-9FFA-B65B57FF5A9D} Third party service" fullword ascii
    $s11 = "  - ServiceName = Windows Update Standalone Installer" fullword ascii
    $s12 = "Validating signature for C:\\Windows\\SoftwareDistribution\\Download\\fbffd999691b70a044083664d2fb7c25_ctc\\Windows6.1-KB2999226" ascii
    $s13 = "Validating signature for C:\\Windows\\SoftwareDistribution\\ScanFile\\9d085694-7e0b-4598-b6c9-47d08f306a11\\Source.cab:" fullword ascii
    $s14 = "Validating signature for C:\\Windows\\SoftwareDistribution\\ScanFile\\2b4e3c91-ac39-462d-9ffa-b65b57ff5a9d\\Source.cab:" fullword ascii
    $s15 = "Validating signature for C:\\Windows\\SoftwareDistribution\\ScanFile\\5d2c4541-99ac-4c50-917f-b6fe22c2a61b\\Source.cab:" fullword ascii
    $s16 = "Validating signature for C:\\Windows\\SoftwareDistribution\\ScanFile\\a249cf70-4a46-4da4-b8e3-9276e3c7c856\\Source.cab:" fullword ascii
    $s17 = "===========  Logging initialized (build: 7.5.7601.17514, tz: -0700)  ===========" fullword ascii
    $s18 = "  * Computer Brand = VMware, Inc." fullword ascii
    $s19 = "  * Computer Model = VMware Virtual Platform" fullword ascii
    $s20 = "===========  Logging initialized (build: 7.5.7601.17514, tz: -0800)  ===========" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "895fbb56c02c3d2bca3125cef5da8730" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}