rule TTP_XOR_WriteProcessMemory_d5a9 {
  strings:
    $key_d5a9 = { 82 db [2] b0 f9 [2] b6 cc [2] 98 cc [2] a7 d0 }

  condition:
    any of them
}