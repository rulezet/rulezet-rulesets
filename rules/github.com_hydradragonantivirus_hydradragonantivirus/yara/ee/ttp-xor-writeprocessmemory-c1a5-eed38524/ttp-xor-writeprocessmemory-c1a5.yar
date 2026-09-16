rule TTP_XOR_WriteProcessMemory_c1a5 {
  strings:
    $key_c1a5 = { 96 d7 [2] a4 f5 [2] a2 c0 [2] 8c c0 [2] b3 dc }

  condition:
    any of them
}