rule TTP_XOR_WriteProcessMemory_12c9 {
  strings:
    $key_12c9 = { 45 bb [2] 77 99 [2] 71 ac [2] 5f ac [2] 60 b0 }

  condition:
    any of them
}