rule TTP_XOR_WriteProcessMemory_87c9 {
  strings:
    $key_87c9 = { d0 bb [2] e2 99 [2] e4 ac [2] ca ac [2] f5 b0 }

  condition:
    any of them
}