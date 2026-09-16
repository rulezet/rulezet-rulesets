rule TTP_XOR_WriteProcessMemory_4767 {
  strings:
    $key_4767 = { 10 15 [2] 22 37 [2] 24 02 [2] 0a 02 [2] 35 1e }

  condition:
    any of them
}