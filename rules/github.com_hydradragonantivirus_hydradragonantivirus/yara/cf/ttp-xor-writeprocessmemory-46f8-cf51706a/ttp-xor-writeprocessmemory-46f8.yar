rule TTP_XOR_WriteProcessMemory_46f8 {
  strings:
    $key_46f8 = { 11 8a [2] 23 a8 [2] 25 9d [2] 0b 9d [2] 34 81 }

  condition:
    any of them
}