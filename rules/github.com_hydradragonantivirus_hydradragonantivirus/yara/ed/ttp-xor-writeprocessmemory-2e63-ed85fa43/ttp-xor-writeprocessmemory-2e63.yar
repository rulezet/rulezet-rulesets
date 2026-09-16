rule TTP_XOR_WriteProcessMemory_2e63 {
  strings:
    $key_2e63 = { 79 11 [2] 4b 33 [2] 4d 06 [2] 63 06 [2] 5c 1a }

  condition:
    any of them
}