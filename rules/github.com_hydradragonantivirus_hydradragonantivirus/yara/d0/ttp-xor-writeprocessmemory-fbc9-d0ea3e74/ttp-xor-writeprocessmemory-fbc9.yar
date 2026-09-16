rule TTP_XOR_WriteProcessMemory_fbc9 {
  strings:
    $key_fbc9 = { ac bb [2] 9e 99 [2] 98 ac [2] b6 ac [2] 89 b0 }

  condition:
    any of them
}