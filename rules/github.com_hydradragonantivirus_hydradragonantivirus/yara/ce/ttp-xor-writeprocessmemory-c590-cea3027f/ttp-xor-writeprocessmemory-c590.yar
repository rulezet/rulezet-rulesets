rule TTP_XOR_WriteProcessMemory_c590 {
  strings:
    $key_c590 = { 92 e2 [2] a0 c0 [2] a6 f5 [2] 88 f5 [2] b7 e9 }

  condition:
    any of them
}