rule TTP_XOR_WriteProcessMemory_c4a9 {
  strings:
    $key_c4a9 = { 93 db [2] a1 f9 [2] a7 cc [2] 89 cc [2] b6 d0 }

  condition:
    any of them
}