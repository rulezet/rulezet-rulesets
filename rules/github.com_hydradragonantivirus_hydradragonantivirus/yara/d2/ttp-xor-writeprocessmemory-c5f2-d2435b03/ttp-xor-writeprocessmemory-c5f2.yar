rule TTP_XOR_WriteProcessMemory_c5f2 {
  strings:
    $key_c5f2 = { 92 80 [2] a0 a2 [2] a6 97 [2] 88 97 [2] b7 8b }

  condition:
    any of them
}