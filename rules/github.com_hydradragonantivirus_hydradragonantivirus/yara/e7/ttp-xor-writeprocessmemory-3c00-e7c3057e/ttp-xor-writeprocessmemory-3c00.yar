rule TTP_XOR_WriteProcessMemory_3c00 {
  strings:
    $key_3c00 = { 6b 72 [2] 59 50 [2] 5f 65 [2] 71 65 [2] 4e 79 }

  condition:
    any of them
}