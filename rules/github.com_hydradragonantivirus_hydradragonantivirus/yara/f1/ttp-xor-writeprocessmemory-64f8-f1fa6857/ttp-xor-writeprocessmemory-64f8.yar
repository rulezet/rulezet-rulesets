rule TTP_XOR_WriteProcessMemory_64f8 {
  strings:
    $key_64f8 = { 33 8a [2] 01 a8 [2] 07 9d [2] 29 9d [2] 16 81 }

  condition:
    any of them
}