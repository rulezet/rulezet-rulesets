rule TTP_XOR_WriteProcessMemory_cbc9 {
  strings:
    $key_cbc9 = { 9c bb [2] ae 99 [2] a8 ac [2] 86 ac [2] b9 b0 }

  condition:
    any of them
}