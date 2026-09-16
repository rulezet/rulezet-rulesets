rule TTP_XOR_WriteProcessMemory_7643 {
  strings:
    $key_7643 = { 21 31 [2] 13 13 [2] 15 26 [2] 3b 26 [2] 04 3a }

  condition:
    any of them
}