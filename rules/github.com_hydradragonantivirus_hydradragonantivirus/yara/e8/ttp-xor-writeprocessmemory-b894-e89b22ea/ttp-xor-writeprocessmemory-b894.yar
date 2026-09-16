rule TTP_XOR_WriteProcessMemory_b894 {
  strings:
    $key_b894 = { ef e6 [2] dd c4 [2] db f1 [2] f5 f1 [2] ca ed }

  condition:
    any of them
}