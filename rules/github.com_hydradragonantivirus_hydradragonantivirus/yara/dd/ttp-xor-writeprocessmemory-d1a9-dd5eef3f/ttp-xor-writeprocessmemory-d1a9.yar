rule TTP_XOR_WriteProcessMemory_d1a9 {
  strings:
    $key_d1a9 = { 86 db [2] b4 f9 [2] b2 cc [2] 9c cc [2] a3 d0 }

  condition:
    any of them
}