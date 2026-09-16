rule TTP_XOR_WriteProcessMemory_7342 {
  strings:
    $key_7342 = { 24 30 [2] 16 12 [2] 10 27 [2] 3e 27 [2] 01 3b }

  condition:
    any of them
}