rule TTP_XOR_WriteProcessMemory_fc51 {
  strings:
    $key_fc51 = { ab 23 [2] 99 01 [2] 9f 34 [2] b1 34 [2] 8e 28 }

  condition:
    any of them
}