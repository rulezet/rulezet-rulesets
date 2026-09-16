rule TTP_XOR_WriteProcessMemory_e9c9 {
  strings:
    $key_e9c9 = { be bb [2] 8c 99 [2] 8a ac [2] a4 ac [2] 9b b0 }

  condition:
    any of them
}