rule TTP_XOR_WriteProcessMemory_d3a9 {
  strings:
    $key_d3a9 = { 84 db [2] b6 f9 [2] b0 cc [2] 9e cc [2] a1 d0 }

  condition:
    any of them
}