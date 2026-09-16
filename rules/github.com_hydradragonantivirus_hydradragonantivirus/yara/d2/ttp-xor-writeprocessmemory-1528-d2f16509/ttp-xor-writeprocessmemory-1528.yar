rule TTP_XOR_WriteProcessMemory_1528 {
  strings:
    $key_1528 = { 42 5a [2] 70 78 [2] 76 4d [2] 58 4d [2] 67 51 }

  condition:
    any of them
}