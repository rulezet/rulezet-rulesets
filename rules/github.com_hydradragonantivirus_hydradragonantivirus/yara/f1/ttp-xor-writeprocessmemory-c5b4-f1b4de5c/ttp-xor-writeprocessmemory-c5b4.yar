rule TTP_XOR_WriteProcessMemory_c5b4 {
  strings:
    $key_c5b4 = { 92 c6 [2] a0 e4 [2] a6 d1 [2] 88 d1 [2] b7 cd }

  condition:
    any of them
}