rule TTP_XOR_WriteProcessMemory_0b49 {
  strings:
    $key_0b49 = { 5c 3b [2] 6e 19 [2] 68 2c [2] 46 2c [2] 79 30 }

  condition:
    any of them
}