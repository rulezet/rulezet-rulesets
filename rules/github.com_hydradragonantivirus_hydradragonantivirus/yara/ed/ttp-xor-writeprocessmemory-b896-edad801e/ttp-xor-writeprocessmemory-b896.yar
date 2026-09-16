rule TTP_XOR_WriteProcessMemory_b896 {
  strings:
    $key_b896 = { ef e4 [2] dd c6 [2] db f3 [2] f5 f3 [2] ca ef }

  condition:
    any of them
}