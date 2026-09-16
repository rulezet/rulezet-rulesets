rule TTP_XOR_WriteProcessMemory_d407 {
  strings:
    $key_d407 = { 83 75 [2] b1 57 [2] b7 62 [2] 99 62 [2] a6 7e }

  condition:
    any of them
}