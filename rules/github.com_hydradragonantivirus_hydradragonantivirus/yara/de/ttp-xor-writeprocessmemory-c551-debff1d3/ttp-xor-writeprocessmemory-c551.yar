rule TTP_XOR_WriteProcessMemory_c551 {
  strings:
    $key_c551 = { 92 23 [2] a0 01 [2] a6 34 [2] 88 34 [2] b7 28 }

  condition:
    any of them
}