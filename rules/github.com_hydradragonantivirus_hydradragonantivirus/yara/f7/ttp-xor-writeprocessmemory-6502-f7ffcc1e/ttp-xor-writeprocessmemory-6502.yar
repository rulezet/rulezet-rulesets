rule TTP_XOR_WriteProcessMemory_6502 {
  strings:
    $key_6502 = { 32 70 [2] 00 52 [2] 06 67 [2] 28 67 [2] 17 7b }

  condition:
    any of them
}