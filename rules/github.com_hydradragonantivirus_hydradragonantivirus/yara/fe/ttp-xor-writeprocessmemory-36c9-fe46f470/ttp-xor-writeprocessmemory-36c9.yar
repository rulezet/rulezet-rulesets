rule TTP_XOR_WriteProcessMemory_36c9 {
  strings:
    $key_36c9 = { 61 bb [2] 53 99 [2] 55 ac [2] 7b ac [2] 44 b0 }

  condition:
    any of them
}