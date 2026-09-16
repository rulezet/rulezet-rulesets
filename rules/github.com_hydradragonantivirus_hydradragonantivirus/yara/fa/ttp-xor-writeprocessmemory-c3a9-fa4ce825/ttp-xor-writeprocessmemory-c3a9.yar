rule TTP_XOR_WriteProcessMemory_c3a9 {
  strings:
    $key_c3a9 = { 94 db [2] a6 f9 [2] a0 cc [2] 8e cc [2] b1 d0 }

  condition:
    any of them
}