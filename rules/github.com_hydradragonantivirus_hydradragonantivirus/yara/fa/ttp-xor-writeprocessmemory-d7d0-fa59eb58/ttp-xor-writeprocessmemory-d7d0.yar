rule TTP_XOR_WriteProcessMemory_d7d0 {
  strings:
    $key_d7d0 = { 80 a2 [2] b2 80 [2] b4 b5 [2] 9a b5 [2] a5 a9 }

  condition:
    any of them
}