rule TTP_XOR_WriteProcessMemory_1af8 {
  strings:
    $key_1af8 = { 4d 8a [2] 7f a8 [2] 79 9d [2] 57 9d [2] 68 81 }

  condition:
    any of them
}