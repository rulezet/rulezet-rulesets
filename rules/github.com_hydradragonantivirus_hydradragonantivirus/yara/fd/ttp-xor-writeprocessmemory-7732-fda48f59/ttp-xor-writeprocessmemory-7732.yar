rule TTP_XOR_WriteProcessMemory_7732 {
  strings:
    $key_7732 = { 20 40 [2] 12 62 [2] 14 57 [2] 3a 57 [2] 05 4b }

  condition:
    any of them
}