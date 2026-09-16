rule TTP_XOR_WriteProcessMemory_25d5 {
  strings:
    $key_25d5 = { 72 a7 [2] 40 85 [2] 46 b0 [2] 68 b0 [2] 57 ac }

  condition:
    any of them
}