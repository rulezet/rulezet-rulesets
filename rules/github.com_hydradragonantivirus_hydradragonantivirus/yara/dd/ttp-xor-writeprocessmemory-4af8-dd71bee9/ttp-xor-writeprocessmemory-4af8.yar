rule TTP_XOR_WriteProcessMemory_4af8 {
  strings:
    $key_4af8 = { 1d 8a [2] 2f a8 [2] 29 9d [2] 07 9d [2] 38 81 }

  condition:
    any of them
}