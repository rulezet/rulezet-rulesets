rule TTP_XOR_WriteProcessMemory_3443 {
  strings:
    $key_3443 = { 63 31 [2] 51 13 [2] 57 26 [2] 79 26 [2] 46 3a }

  condition:
    any of them
}