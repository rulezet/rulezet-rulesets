rule TTP_XOR_WriteProcessMemory_afb4 {
  strings:
    $key_afb4 = { f8 c6 [2] ca e4 [2] cc d1 [2] e2 d1 [2] dd cd }

  condition:
    any of them
}