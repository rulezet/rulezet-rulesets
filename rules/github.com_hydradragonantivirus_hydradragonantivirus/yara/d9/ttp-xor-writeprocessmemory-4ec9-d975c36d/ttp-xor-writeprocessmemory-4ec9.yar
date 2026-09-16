rule TTP_XOR_WriteProcessMemory_4ec9 {
  strings:
    $key_4ec9 = { 19 bb [2] 2b 99 [2] 2d ac [2] 03 ac [2] 3c b0 }

  condition:
    any of them
}