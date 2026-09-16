rule TTP_XOR_WriteProcessMemory_4c46 {
  strings:
    $key_4c46 = { 1b 34 [2] 29 16 [2] 2f 23 [2] 01 23 [2] 3e 3f }

  condition:
    any of them
}