rule TTP_XOR_WriteProcessMemory_d1c0 {
  strings:
    $key_d1c0 = { 86 b2 [2] b4 90 [2] b2 a5 [2] 9c a5 [2] a3 b9 }

  condition:
    any of them
}