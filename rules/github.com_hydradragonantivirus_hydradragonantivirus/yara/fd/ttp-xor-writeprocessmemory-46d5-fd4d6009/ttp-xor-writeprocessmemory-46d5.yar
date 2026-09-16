rule TTP_XOR_WriteProcessMemory_46d5 {
  strings:
    $key_46d5 = { 11 a7 [2] 23 85 [2] 25 b0 [2] 0b b0 [2] 34 ac }

  condition:
    any of them
}