rule TTP_XOR_WriteProcessMemory_d291 {
  strings:
    $key_d291 = { 85 e3 [2] b7 c1 [2] b1 f4 [2] 9f f4 [2] a0 e8 }

  condition:
    any of them
}