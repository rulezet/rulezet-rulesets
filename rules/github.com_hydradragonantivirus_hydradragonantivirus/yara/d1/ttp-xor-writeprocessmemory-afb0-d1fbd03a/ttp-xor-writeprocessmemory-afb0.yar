rule TTP_XOR_WriteProcessMemory_afb0 {
  strings:
    $key_afb0 = { f8 c2 [2] ca e0 [2] cc d5 [2] e2 d5 [2] dd c9 }

  condition:
    any of them
}