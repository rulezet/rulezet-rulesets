rule TTP_XOR_WriteProcessMemory_c597 {
  strings:
    $key_c597 = { 92 e5 [2] a0 c7 [2] a6 f2 [2] 88 f2 [2] b7 ee }

  condition:
    any of them
}