rule TTP_XOR_WriteProcessMemory_c8c9 {
  strings:
    $key_c8c9 = { 9f bb [2] ad 99 [2] ab ac [2] 85 ac [2] ba b0 }

  condition:
    any of them
}