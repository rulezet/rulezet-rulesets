rule TTP_XOR_WriteProcessMemory_5000 {
  strings:
    $key_5000 = { 07 72 [2] 35 50 [2] 33 65 [2] 1d 65 [2] 22 79 }

  condition:
    any of them
}