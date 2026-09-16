rule TTP_XOR_WriteProcessMemory_60c9 {
  strings:
    $key_60c9 = { 37 bb [2] 05 99 [2] 03 ac [2] 2d ac [2] 12 b0 }

  condition:
    any of them
}