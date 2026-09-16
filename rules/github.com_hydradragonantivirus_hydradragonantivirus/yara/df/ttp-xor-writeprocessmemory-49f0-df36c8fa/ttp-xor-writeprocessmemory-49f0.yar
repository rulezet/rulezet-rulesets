rule TTP_XOR_WriteProcessMemory_49f0 {
  strings:
    $key_49f0 = { 1e 82 [2] 2c a0 [2] 2a 95 [2] 04 95 [2] 3b 89 }

  condition:
    any of them
}