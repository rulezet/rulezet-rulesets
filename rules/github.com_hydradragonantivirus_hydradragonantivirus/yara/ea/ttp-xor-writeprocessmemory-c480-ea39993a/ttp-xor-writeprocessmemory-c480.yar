rule TTP_XOR_WriteProcessMemory_c480 {
  strings:
    $key_c480 = { 93 f2 [2] a1 d0 [2] a7 e5 [2] 89 e5 [2] b6 f9 }

  condition:
    any of them
}