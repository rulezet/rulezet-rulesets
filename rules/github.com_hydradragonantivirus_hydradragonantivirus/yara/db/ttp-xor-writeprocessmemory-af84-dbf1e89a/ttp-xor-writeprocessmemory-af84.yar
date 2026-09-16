rule TTP_XOR_WriteProcessMemory_af84 {
  strings:
    $key_af84 = { f8 f6 [2] ca d4 [2] cc e1 [2] e2 e1 [2] dd fd }

  condition:
    any of them
}