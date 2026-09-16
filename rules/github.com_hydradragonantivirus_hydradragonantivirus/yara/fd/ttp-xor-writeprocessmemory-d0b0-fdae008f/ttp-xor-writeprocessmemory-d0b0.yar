rule TTP_XOR_WriteProcessMemory_d0b0 {
  strings:
    $key_d0b0 = { 87 c2 [2] b5 e0 [2] b3 d5 [2] 9d d5 [2] a2 c9 }

  condition:
    any of them
}