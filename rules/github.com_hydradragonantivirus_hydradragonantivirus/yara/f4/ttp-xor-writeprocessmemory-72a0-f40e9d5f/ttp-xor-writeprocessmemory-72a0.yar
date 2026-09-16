rule TTP_XOR_WriteProcessMemory_72a0 {
  strings:
    $key_72a0 = { 25 d2 [2] 17 f0 [2] 11 c5 [2] 3f c5 [2] 00 d9 }

  condition:
    any of them
}