rule TTP_XOR_WriteProcessMemory_7100 {
  strings:
    $key_7100 = { 26 72 [2] 14 50 [2] 12 65 [2] 3c 65 [2] 03 79 }

  condition:
    any of them
}