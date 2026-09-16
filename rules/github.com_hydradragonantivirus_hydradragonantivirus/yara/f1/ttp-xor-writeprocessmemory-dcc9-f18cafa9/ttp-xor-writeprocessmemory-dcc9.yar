rule TTP_XOR_WriteProcessMemory_dcc9 {
  strings:
    $key_dcc9 = { 8b bb [2] b9 99 [2] bf ac [2] 91 ac [2] ae b0 }

  condition:
    any of them
}