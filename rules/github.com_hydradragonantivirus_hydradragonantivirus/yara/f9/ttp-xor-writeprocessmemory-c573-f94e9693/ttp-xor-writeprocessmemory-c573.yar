rule TTP_XOR_WriteProcessMemory_c573 {
  strings:
    $key_c573 = { 92 01 [2] a0 23 [2] a6 16 [2] 88 16 [2] b7 0a }

  condition:
    any of them
}