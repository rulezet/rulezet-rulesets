rule TTP_XOR_WriteProcessMemory_d090 {
  strings:
    $key_d090 = { 87 e2 [2] b5 c0 [2] b3 f5 [2] 9d f5 [2] a2 e9 }

  condition:
    any of them
}