rule TTP_XOR_WriteProcessMemory_10f0 {
  strings:
    $key_10f0 = { 47 82 [2] 75 a0 [2] 73 95 [2] 5d 95 [2] 62 89 }

  condition:
    any of them
}