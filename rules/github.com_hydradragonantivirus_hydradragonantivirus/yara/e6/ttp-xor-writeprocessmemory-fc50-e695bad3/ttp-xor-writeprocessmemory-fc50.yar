rule TTP_XOR_WriteProcessMemory_fc50 {
  strings:
    $key_fc50 = { ab 22 [2] 99 00 [2] 9f 35 [2] b1 35 [2] 8e 29 }

  condition:
    any of them
}