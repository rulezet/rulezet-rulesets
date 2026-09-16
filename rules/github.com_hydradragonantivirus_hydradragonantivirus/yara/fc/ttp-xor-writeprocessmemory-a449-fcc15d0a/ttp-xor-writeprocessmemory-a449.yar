rule TTP_XOR_WriteProcessMemory_a449 {
  strings:
    $key_a449 = { f3 3b [2] c1 19 [2] c7 2c [2] e9 2c [2] d6 30 }

  condition:
    any of them
}