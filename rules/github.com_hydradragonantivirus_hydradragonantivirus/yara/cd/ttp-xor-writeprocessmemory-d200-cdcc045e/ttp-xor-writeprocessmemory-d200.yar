rule TTP_XOR_WriteProcessMemory_d200 {
  strings:
    $key_d200 = { 85 72 [2] b7 50 [2] b1 65 [2] 9f 65 [2] a0 79 }

  condition:
    any of them
}