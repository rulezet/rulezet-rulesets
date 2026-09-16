rule TTP_XOR_WriteProcessMemory_86c9 {
  strings:
    $key_86c9 = { d1 bb [2] e3 99 [2] e5 ac [2] cb ac [2] f4 b0 }

  condition:
    any of them
}