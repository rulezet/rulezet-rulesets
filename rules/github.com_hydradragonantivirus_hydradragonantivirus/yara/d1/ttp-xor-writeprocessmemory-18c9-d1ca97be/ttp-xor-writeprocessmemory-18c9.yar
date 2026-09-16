rule TTP_XOR_WriteProcessMemory_18c9 {
  strings:
    $key_18c9 = { 4f bb [2] 7d 99 [2] 7b ac [2] 55 ac [2] 6a b0 }

  condition:
    any of them
}