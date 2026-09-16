rule TTP_XOR_WriteProcessMemory_c4c4 {
  strings:
    $key_c4c4 = { 93 b6 [2] a1 94 [2] a7 a1 [2] 89 a1 [2] b6 bd }

  condition:
    any of them
}