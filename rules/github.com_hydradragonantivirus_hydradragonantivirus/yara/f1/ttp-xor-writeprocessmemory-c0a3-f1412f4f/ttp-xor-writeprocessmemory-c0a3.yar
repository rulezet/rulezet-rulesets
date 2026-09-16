rule TTP_XOR_WriteProcessMemory_c0a3 {
  strings:
    $key_c0a3 = { 97 d1 [2] a5 f3 [2] a3 c6 [2] 8d c6 [2] b2 da }

  condition:
    any of them
}