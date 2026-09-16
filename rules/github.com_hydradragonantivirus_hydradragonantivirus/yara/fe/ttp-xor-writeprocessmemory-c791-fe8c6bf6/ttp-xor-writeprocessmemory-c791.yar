rule TTP_XOR_WriteProcessMemory_c791 {
  strings:
    $key_c791 = { 90 e3 [2] a2 c1 [2] a4 f4 [2] 8a f4 [2] b5 e8 }

  condition:
    any of them
}