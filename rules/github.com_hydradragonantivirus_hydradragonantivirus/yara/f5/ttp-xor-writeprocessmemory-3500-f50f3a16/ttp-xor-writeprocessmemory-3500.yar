rule TTP_XOR_WriteProcessMemory_3500 {
  strings:
    $key_3500 = { 62 72 [2] 50 50 [2] 56 65 [2] 78 65 [2] 47 79 }

  condition:
    any of them
}