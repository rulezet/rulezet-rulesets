rule TTP_XOR_WriteProcessMemory_fc55 {
  strings:
    $key_fc55 = { ab 27 [2] 99 05 [2] 9f 30 [2] b1 30 [2] 8e 2c }

  condition:
    any of them
}