rule TTP_XOR_WriteProcessMemory_c4a3 {
  strings:
    $key_c4a3 = { 93 d1 [2] a1 f3 [2] a7 c6 [2] 89 c6 [2] b6 da }

  condition:
    any of them
}