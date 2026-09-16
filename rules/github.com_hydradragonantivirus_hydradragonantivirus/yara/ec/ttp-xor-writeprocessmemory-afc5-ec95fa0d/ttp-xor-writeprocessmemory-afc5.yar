rule TTP_XOR_WriteProcessMemory_afc5 {
  strings:
    $key_afc5 = { f8 b7 [2] ca 95 [2] cc a0 [2] e2 a0 [2] dd bc }

  condition:
    any of them
}