rule TTP_XOR_WriteProcessMemory_85c9 {
  strings:
    $key_85c9 = { d2 bb [2] e0 99 [2] e6 ac [2] c8 ac [2] f7 b0 }

  condition:
    any of them
}