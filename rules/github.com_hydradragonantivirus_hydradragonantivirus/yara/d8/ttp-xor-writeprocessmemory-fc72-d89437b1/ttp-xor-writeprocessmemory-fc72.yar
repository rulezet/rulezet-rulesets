rule TTP_XOR_WriteProcessMemory_fc72 {
  strings:
    $key_fc72 = { ab 00 [2] 99 22 [2] 9f 17 [2] b1 17 [2] 8e 0b }

  condition:
    any of them
}