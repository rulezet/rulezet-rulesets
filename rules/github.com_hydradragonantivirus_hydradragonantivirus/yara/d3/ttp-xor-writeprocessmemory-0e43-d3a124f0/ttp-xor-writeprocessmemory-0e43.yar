rule TTP_XOR_WriteProcessMemory_0e43 {
  strings:
    $key_0e43 = { 59 31 [2] 6b 13 [2] 6d 26 [2] 43 26 [2] 7c 3a }

  condition:
    any of them
}