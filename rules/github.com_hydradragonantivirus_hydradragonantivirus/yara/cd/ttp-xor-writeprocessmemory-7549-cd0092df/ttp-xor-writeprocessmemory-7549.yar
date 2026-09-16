rule TTP_XOR_WriteProcessMemory_7549 {
  strings:
    $key_7549 = { 22 3b [2] 10 19 [2] 16 2c [2] 38 2c [2] 07 30 }

  condition:
    any of them
}