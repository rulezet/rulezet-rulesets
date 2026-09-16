rule TTP_XOR_WriteProcessMemory_e549 {
  strings:
    $key_e549 = { b2 3b [2] 80 19 [2] 86 2c [2] a8 2c [2] 97 30 }

  condition:
    any of them
}