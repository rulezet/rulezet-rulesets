rule TTP_XOR_WriteProcessMemory_dcc5 {
  strings:
    $key_dcc5 = { 8b b7 [2] b9 95 [2] bf a0 [2] 91 a0 [2] ae bc }

  condition:
    any of them
}