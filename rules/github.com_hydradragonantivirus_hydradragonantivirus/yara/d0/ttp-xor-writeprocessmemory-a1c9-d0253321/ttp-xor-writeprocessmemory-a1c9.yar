rule TTP_XOR_WriteProcessMemory_a1c9 {
  strings:
    $key_a1c9 = { f6 bb [2] c4 99 [2] c2 ac [2] ec ac [2] d3 b0 }

  condition:
    any of them
}