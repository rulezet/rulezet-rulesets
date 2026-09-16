rule TTP_XOR_WriteProcessMemory_25d9 {
  strings:
    $key_25d9 = { 72 ab [2] 40 89 [2] 46 bc [2] 68 bc [2] 57 a0 }

  condition:
    any of them
}