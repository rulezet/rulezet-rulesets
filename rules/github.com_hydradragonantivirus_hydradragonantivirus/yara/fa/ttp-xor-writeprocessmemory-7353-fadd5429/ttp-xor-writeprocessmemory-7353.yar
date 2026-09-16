rule TTP_XOR_WriteProcessMemory_7353 {
  strings:
    $key_7353 = { 24 21 [2] 16 03 [2] 10 36 [2] 3e 36 [2] 01 2a }

  condition:
    any of them
}