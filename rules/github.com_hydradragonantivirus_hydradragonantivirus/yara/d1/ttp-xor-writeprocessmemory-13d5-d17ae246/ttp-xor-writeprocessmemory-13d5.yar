rule TTP_XOR_WriteProcessMemory_13d5 {
  strings:
    $key_13d5 = { 44 a7 [2] 76 85 [2] 70 b0 [2] 5e b0 [2] 61 ac }

  condition:
    any of them
}