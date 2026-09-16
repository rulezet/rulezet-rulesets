rule TTP_XOR_WriteProcessMemory_c7a3 {
  strings:
    $key_c7a3 = { 90 d1 [2] a2 f3 [2] a4 c6 [2] 8a c6 [2] b5 da }

  condition:
    any of them
}