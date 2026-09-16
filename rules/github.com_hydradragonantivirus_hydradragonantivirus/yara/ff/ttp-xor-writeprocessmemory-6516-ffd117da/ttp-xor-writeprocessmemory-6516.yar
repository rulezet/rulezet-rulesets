rule TTP_XOR_WriteProcessMemory_6516 {
  strings:
    $key_6516 = { 32 64 [2] 00 46 [2] 06 73 [2] 28 73 [2] 17 6f }

  condition:
    any of them
}