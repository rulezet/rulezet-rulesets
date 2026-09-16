rule TTP_XOR_WriteProcessMemory_1e43 {
  strings:
    $key_1e43 = { 49 31 [2] 7b 13 [2] 7d 26 [2] 53 26 [2] 6c 3a }

  condition:
    any of them
}