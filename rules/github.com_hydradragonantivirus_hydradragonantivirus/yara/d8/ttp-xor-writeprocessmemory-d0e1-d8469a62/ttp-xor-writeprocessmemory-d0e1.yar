rule TTP_XOR_WriteProcessMemory_d0e1 {
  strings:
    $key_d0e1 = { 87 93 [2] b5 b1 [2] b3 84 [2] 9d 84 [2] a2 98 }

  condition:
    any of them
}