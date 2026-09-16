rule TTP_XOR_WriteProcessMemory_c596 {
  strings:
    $key_c596 = { 92 e4 [2] a0 c6 [2] a6 f3 [2] 88 f3 [2] b7 ef }

  condition:
    any of them
}