rule HiddenCobra_r4_wiper_2 {
   meta:
      author = "NCCIC Partner"
      date = "2017-12-12"
      description = "Detects HiddenCobra Wiper"
      reference = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
      id = "75acc3cb-90dd-58e8-b094-ed3f28650b1b"
   strings:
            $PhysicalDriveSTR = "\\\\.\\PhysicalDrive" wide
      $ExtendedWrite = { B4 43 B0 00 CD 13 }
   condition:
      uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550 and all of them
}