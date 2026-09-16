rule TTP_XOR_WriteProcessMemory_55c9 {
  strings:
    $key_55c9 = { 02 bb [2] 30 99 [2] 36 ac [2] 18 ac [2] 27 b0 }

  condition:
    any of them
}