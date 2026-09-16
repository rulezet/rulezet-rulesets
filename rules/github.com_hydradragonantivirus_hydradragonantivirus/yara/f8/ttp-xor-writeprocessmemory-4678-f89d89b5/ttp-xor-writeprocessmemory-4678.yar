rule TTP_XOR_WriteProcessMemory_4678 {
  strings:
    $key_4678 = { 11 0a [2] 23 28 [2] 25 1d [2] 0b 1d [2] 34 01 }

  condition:
    any of them
}