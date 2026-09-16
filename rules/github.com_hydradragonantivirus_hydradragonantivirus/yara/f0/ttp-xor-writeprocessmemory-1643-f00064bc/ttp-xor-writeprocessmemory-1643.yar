rule TTP_XOR_WriteProcessMemory_1643 {
  strings:
    $key_1643 = { 41 31 [2] 73 13 [2] 75 26 [2] 5b 26 [2] 64 3a }

  condition:
    any of them
}