rule TTP_XOR_WriteProcessMemory_af89 {
  strings:
    $key_af89 = { f8 fb [2] ca d9 [2] cc ec [2] e2 ec [2] dd f0 }

  condition:
    any of them
}