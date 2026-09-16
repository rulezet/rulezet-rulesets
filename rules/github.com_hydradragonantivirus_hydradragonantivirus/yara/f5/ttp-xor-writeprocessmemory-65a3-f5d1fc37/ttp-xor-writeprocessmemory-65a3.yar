rule TTP_XOR_WriteProcessMemory_65a3 {
  strings:
    $key_65a3 = { 32 d1 [2] 00 f3 [2] 06 c6 [2] 28 c6 [2] 17 da }

  condition:
    any of them
}