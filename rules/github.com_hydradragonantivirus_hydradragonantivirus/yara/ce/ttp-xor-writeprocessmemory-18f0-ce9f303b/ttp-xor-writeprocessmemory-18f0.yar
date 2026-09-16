rule TTP_XOR_WriteProcessMemory_18f0 {
  strings:
    $key_18f0 = { 4f 82 [2] 7d a0 [2] 7b 95 [2] 55 95 [2] 6a 89 }

  condition:
    any of them
}