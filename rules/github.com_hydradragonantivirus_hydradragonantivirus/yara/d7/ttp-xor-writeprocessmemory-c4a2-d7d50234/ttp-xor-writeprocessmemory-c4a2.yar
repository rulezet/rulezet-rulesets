rule TTP_XOR_WriteProcessMemory_c4a2 {
  strings:
    $key_c4a2 = { 93 d0 [2] a1 f2 [2] a7 c7 [2] 89 c7 [2] b6 db }

  condition:
    any of them
}