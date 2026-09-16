rule TTP_XOR_WriteProcessMemory_65d9 {
  strings:
    $key_65d9 = { 32 ab [2] 00 89 [2] 06 bc [2] 28 bc [2] 17 a0 }

  condition:
    any of them
}