rule TTP_XOR_WriteProcessMemory_73d9 {
  strings:
    $key_73d9 = { 24 ab [2] 16 89 [2] 10 bc [2] 3e bc [2] 01 a0 }

  condition:
    any of them
}