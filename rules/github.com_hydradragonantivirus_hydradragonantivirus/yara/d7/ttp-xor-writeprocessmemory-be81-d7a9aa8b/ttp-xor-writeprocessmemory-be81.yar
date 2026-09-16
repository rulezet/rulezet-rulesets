rule TTP_XOR_WriteProcessMemory_be81 {
  strings:
    $key_be81 = { e9 f3 [2] db d1 [2] dd e4 [2] f3 e4 [2] cc f8 }

  condition:
    any of them
}