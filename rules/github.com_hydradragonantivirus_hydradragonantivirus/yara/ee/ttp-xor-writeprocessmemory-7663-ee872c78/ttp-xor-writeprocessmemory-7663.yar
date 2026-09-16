rule TTP_XOR_WriteProcessMemory_7663 {
  strings:
    $key_7663 = { 21 11 [2] 13 33 [2] 15 06 [2] 3b 06 [2] 04 1a }

  condition:
    any of them
}