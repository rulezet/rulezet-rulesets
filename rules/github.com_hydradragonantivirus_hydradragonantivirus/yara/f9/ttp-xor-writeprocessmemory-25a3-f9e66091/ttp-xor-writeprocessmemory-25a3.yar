rule TTP_XOR_WriteProcessMemory_25a3 {
  strings:
    $key_25a3 = { 72 d1 [2] 40 f3 [2] 46 c6 [2] 68 c6 [2] 57 da }

  condition:
    any of them
}