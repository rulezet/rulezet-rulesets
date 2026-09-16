rule TTP_XOR_WriteProcessMemory_2bc9 {
  strings:
    $key_2bc9 = { 7c bb [2] 4e 99 [2] 48 ac [2] 66 ac [2] 59 b0 }

  condition:
    any of them
}