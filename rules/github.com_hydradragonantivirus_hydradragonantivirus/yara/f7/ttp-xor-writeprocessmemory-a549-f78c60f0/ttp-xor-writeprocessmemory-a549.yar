rule TTP_XOR_WriteProcessMemory_a549 {
  strings:
    $key_a549 = { f2 3b [2] c0 19 [2] c6 2c [2] e8 2c [2] d7 30 }

  condition:
    any of them
}