rule TTP_XOR_WriteProcessMemory_1e63 {
  strings:
    $key_1e63 = { 49 11 [2] 7b 33 [2] 7d 06 [2] 53 06 [2] 6c 1a }

  condition:
    any of them
}