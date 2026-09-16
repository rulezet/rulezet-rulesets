rule TTP_XOR_WriteProcessMemory_f549 {
  strings:
    $key_f549 = { a2 3b [2] 90 19 [2] 96 2c [2] b8 2c [2] 87 30 }

  condition:
    any of them
}