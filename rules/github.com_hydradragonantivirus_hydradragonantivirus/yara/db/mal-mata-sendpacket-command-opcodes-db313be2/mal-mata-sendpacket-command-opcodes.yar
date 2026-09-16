rule MAL_MATA_SendPacket_Command_Opcodes {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-18"
    version     = "1.0"
    description = "check for Mata framework packet opcodes being moved into EDI before sending"

  strings:
    $0x20300 = { bf 00 03 02 00 31 f6 31 d2 e8 }
    $0x20600 = { bf 00 06 02 00 31 f6 49 89 d5 31 d2 e8 }
    $0x20500 = { bf 00 05 02 00 31 f6 31 d2 e8 }
  

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    all of them
}