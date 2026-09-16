rule TTP_XOR_WriteProcessMemory_7700 {
  strings:
    $key_7700 = { 20 72 [2] 12 50 [2] 14 65 [2] 3a 65 [2] 05 79 }

  condition:
    any of them
}