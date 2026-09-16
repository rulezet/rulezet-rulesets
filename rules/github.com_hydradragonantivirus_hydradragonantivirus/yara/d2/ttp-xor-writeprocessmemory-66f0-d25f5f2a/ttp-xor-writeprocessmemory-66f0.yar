rule TTP_XOR_WriteProcessMemory_66f0 {
  strings:
    $key_66f0 = { 31 82 [2] 03 a0 [2] 05 95 [2] 2b 95 [2] 14 89 }

  condition:
    any of them
}