rule TTP_XOR_WriteProcessMemory_d490 {
  strings:
    $key_d490 = { 83 e2 [2] b1 c0 [2] b7 f5 [2] 99 f5 [2] a6 e9 }

  condition:
    any of them
}