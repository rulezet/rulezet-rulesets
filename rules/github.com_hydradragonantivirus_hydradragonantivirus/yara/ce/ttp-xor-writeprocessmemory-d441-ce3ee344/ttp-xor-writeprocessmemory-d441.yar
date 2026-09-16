rule TTP_XOR_WriteProcessMemory_d441 {
  strings:
    $key_d441 = { 83 33 [2] b1 11 [2] b7 24 [2] 99 24 [2] a6 38 }

  condition:
    any of them
}