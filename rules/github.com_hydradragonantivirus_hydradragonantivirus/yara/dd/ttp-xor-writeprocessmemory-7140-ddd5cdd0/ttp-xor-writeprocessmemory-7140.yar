rule TTP_XOR_WriteProcessMemory_7140 {
  strings:
    $key_7140 = { 26 32 [2] 14 10 [2] 12 25 [2] 3c 25 [2] 03 39 }

  condition:
    any of them
}