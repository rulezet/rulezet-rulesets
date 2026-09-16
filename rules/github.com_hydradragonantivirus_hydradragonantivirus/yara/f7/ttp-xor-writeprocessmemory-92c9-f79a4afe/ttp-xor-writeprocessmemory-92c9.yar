rule TTP_XOR_WriteProcessMemory_92c9 {
  strings:
    $key_92c9 = { c5 bb [2] f7 99 [2] f1 ac [2] df ac [2] e0 b0 }

  condition:
    any of them
}