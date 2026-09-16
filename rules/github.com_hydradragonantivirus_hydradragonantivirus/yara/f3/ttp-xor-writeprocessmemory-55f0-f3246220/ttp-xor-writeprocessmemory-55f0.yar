rule TTP_XOR_WriteProcessMemory_55f0 {
  strings:
    $key_55f0 = { 02 82 [2] 30 a0 [2] 36 95 [2] 18 95 [2] 27 89 }

  condition:
    any of them
}