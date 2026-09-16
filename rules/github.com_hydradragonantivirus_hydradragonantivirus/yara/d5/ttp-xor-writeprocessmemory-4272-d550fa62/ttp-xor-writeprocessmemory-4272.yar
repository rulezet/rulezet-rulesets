rule TTP_XOR_WriteProcessMemory_4272 {
  strings:
    $key_4272 = { 15 00 [2] 27 22 [2] 21 17 [2] 0f 17 [2] 30 0b }

  condition:
    any of them
}