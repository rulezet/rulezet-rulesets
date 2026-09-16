rule TTP_XOR_WriteProcessMemory_97c9 {
  strings:
    $key_97c9 = { c0 bb [2] f2 99 [2] f4 ac [2] da ac [2] e5 b0 }

  condition:
    any of them
}