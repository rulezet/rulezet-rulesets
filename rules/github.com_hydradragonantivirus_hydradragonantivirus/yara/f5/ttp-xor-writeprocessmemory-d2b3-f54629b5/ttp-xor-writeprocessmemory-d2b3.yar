rule TTP_XOR_WriteProcessMemory_d2b3 {
  strings:
    $key_d2b3 = { 85 c1 [2] b7 e3 [2] b1 d6 [2] 9f d6 [2] a0 ca }

  condition:
    any of them
}