rule TTP_XOR_WriteProcessMemory_65a4 {
  strings:
    $key_65a4 = { 32 d6 [2] 00 f4 [2] 06 c1 [2] 28 c1 [2] 17 dd }

  condition:
    any of them
}