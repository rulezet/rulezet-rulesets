rule TTP_XOR_WriteProcessMemory_09f0 {
  strings:
    $key_09f0 = { 5e 82 [2] 6c a0 [2] 6a 95 [2] 44 95 [2] 7b 89 }

  condition:
    any of them
}