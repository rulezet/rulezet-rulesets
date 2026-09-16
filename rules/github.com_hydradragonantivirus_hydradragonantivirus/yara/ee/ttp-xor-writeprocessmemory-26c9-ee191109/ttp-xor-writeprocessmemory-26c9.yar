rule TTP_XOR_WriteProcessMemory_26c9 {
  strings:
    $key_26c9 = { 71 bb [2] 43 99 [2] 45 ac [2] 6b ac [2] 54 b0 }

  condition:
    any of them
}