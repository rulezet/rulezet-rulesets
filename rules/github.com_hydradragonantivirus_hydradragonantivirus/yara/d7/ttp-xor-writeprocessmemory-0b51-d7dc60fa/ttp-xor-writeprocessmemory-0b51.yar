rule TTP_XOR_WriteProcessMemory_0b51 {
  strings:
    $key_0b51 = { 5c 23 [2] 6e 01 [2] 68 34 [2] 46 34 [2] 79 28 }

  condition:
    any of them
}