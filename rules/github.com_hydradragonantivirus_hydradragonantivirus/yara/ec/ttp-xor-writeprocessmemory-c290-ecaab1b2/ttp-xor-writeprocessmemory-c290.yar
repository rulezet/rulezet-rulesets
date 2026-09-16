rule TTP_XOR_WriteProcessMemory_c290 {
  strings:
    $key_c290 = { 95 e2 [2] a7 c0 [2] a1 f5 [2] 8f f5 [2] b0 e9 }

  condition:
    any of them
}