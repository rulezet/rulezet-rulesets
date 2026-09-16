rule TTP_XOR_WriteProcessMemory_d7a6 {
  strings:
    $key_d7a6 = { 80 d4 [2] b2 f6 [2] b4 c3 [2] 9a c3 [2] a5 df }

  condition:
    any of them
}