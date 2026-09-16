rule TTP_XOR_WriteProcessMemory_c185 {
  strings:
    $key_c185 = { 96 f7 [2] a4 d5 [2] a2 e0 [2] 8c e0 [2] b3 fc }

  condition:
    any of them
}