rule TTP_XOR_WriteProcessMemory_d7b4 {
  strings:
    $key_d7b4 = { 80 c6 [2] b2 e4 [2] b4 d1 [2] 9a d1 [2] a5 cd }

  condition:
    any of them
}