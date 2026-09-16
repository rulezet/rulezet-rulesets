rule TTP_XOR_WriteProcessMemory_c5d0 {
  strings:
    $key_c5d0 = { 92 a2 [2] a0 80 [2] a6 b5 [2] 88 b5 [2] b7 a9 }

  condition:
    any of them
}