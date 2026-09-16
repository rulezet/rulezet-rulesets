rule TTP_XOR_WriteProcessMemory_6d00 {
  strings:
    $key_6d00 = { 3a 72 [2] 08 50 [2] 0e 65 [2] 20 65 [2] 1f 79 }

  condition:
    any of them
}