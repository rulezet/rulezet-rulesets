rule TTP_XOR_WriteProcessMemory_ede1 {
  strings:
    $key_ede1 = { ba 93 [2] 88 b1 [2] 8e 84 [2] a0 84 [2] 9f 98 }

  condition:
    any of them
}