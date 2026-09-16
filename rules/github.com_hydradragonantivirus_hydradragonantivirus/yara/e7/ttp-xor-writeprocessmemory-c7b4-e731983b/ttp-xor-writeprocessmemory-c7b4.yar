rule TTP_XOR_WriteProcessMemory_c7b4 {
  strings:
    $key_c7b4 = { 90 c6 [2] a2 e4 [2] a4 d1 [2] 8a d1 [2] b5 cd }

  condition:
    any of them
}