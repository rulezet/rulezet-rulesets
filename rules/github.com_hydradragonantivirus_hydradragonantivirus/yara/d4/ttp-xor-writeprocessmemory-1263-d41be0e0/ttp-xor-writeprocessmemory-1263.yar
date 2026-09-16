rule TTP_XOR_WriteProcessMemory_1263 {
  strings:
    $key_1263 = { 45 11 [2] 77 33 [2] 71 06 [2] 5f 06 [2] 60 1a }

  condition:
    any of them
}