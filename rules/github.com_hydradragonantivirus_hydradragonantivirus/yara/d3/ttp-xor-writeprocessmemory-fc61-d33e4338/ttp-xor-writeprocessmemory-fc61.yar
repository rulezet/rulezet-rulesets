rule TTP_XOR_WriteProcessMemory_fc61 {
  strings:
    $key_fc61 = { ab 13 [2] 99 31 [2] 9f 04 [2] b1 04 [2] 8e 18 }

  condition:
    any of them
}