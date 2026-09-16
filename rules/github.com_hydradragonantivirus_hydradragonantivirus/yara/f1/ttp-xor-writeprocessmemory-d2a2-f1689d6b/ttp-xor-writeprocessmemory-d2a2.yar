rule TTP_XOR_WriteProcessMemory_d2a2 {
  strings:
    $key_d2a2 = { 85 d0 [2] b7 f2 [2] b1 c7 [2] 9f c7 [2] a0 db }

  condition:
    any of them
}