rule TTP_XOR_WriteProcessMemory_cdc9 {
  strings:
    $key_cdc9 = { 9a bb [2] a8 99 [2] ae ac [2] 80 ac [2] bf b0 }

  condition:
    any of them
}