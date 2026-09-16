rule TTP_XOR_WriteProcessMemory_15f8 {
  strings:
    $key_15f8 = { 42 8a [2] 70 a8 [2] 76 9d [2] 58 9d [2] 67 81 }

  condition:
    any of them
}