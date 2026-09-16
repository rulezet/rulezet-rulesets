rule TTP_XOR_WriteProcessMemory_afa0 {
  strings:
    $key_afa0 = { f8 d2 [2] ca f0 [2] cc c5 [2] e2 c5 [2] dd d9 }

  condition:
    any of them
}