rule TTP_XOR_WriteProcessMemory_96c6 {
  strings:
    $key_96c6 = { c1 b4 [2] f3 96 [2] f5 a3 [2] db a3 [2] e4 bf }

  condition:
    any of them
}