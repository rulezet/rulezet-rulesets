rule TTP_XOR_WriteProcessMemory_4af0 {
  strings:
    $key_4af0 = { 1d 82 [2] 2f a0 [2] 29 95 [2] 07 95 [2] 38 89 }

  condition:
    any of them
}