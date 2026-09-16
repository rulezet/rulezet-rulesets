rule TTP_XOR_WriteProcessMemory_3353 {
  strings:
    $key_3353 = { 64 21 [2] 56 03 [2] 50 36 [2] 7e 36 [2] 41 2a }

  condition:
    any of them
}