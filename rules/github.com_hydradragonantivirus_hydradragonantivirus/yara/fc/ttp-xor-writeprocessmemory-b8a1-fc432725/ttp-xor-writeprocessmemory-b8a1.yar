rule TTP_XOR_WriteProcessMemory_b8a1 {
  strings:
    $key_b8a1 = { ef d3 [2] dd f1 [2] db c4 [2] f5 c4 [2] ca d8 }

  condition:
    any of them
}