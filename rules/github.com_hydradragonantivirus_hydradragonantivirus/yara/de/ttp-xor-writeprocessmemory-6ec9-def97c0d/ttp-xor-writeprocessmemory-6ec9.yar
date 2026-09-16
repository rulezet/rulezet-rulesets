rule TTP_XOR_WriteProcessMemory_6ec9 {
  strings:
    $key_6ec9 = { 39 bb [2] 0b 99 [2] 0d ac [2] 23 ac [2] 1c b0 }

  condition:
    any of them
}