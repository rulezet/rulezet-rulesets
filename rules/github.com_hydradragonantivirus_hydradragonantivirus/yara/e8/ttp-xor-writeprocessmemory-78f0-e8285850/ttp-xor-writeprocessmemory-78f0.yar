rule TTP_XOR_WriteProcessMemory_78f0 {
  strings:
    $key_78f0 = { 2f 82 [2] 1d a0 [2] 1b 95 [2] 35 95 [2] 0a 89 }

  condition:
    any of them
}