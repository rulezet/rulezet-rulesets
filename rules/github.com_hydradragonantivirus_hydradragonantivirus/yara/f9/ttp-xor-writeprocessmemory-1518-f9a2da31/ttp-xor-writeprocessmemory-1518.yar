rule TTP_XOR_WriteProcessMemory_1518 {
  strings:
    $key_1518 = { 42 6a [2] 70 48 [2] 76 7d [2] 58 7d [2] 67 61 }

  condition:
    any of them
}