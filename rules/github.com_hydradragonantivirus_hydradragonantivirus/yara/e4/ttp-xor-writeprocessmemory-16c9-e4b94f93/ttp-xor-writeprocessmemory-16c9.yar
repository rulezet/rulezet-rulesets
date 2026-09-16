rule TTP_XOR_WriteProcessMemory_16c9 {
  strings:
    $key_16c9 = { 41 bb [2] 73 99 [2] 75 ac [2] 5b ac [2] 64 b0 }

  condition:
    any of them
}