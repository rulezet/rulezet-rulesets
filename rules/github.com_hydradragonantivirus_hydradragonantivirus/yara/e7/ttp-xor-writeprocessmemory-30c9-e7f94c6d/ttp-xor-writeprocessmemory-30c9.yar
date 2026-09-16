rule TTP_XOR_WriteProcessMemory_30c9 {
  strings:
    $key_30c9 = { 67 bb [2] 55 99 [2] 53 ac [2] 7d ac [2] 42 b0 }

  condition:
    any of them
}