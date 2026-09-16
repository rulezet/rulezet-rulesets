rule TTP_XOR_WriteProcessMemory_4573 {
  strings:
    $key_4573 = { 12 01 [2] 20 23 [2] 26 16 [2] 08 16 [2] 37 0a }

  condition:
    any of them
}