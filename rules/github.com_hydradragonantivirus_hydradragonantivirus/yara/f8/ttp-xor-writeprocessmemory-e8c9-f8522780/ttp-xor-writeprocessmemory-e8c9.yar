rule TTP_XOR_WriteProcessMemory_e8c9 {
  strings:
    $key_e8c9 = { bf bb [2] 8d 99 [2] 8b ac [2] a5 ac [2] 9a b0 }

  condition:
    any of them
}