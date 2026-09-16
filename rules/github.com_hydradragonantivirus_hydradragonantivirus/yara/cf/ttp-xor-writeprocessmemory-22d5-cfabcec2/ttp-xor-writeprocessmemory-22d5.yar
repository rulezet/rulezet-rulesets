rule TTP_XOR_WriteProcessMemory_22d5 {
  strings:
    $key_22d5 = { 75 a7 [2] 47 85 [2] 41 b0 [2] 6f b0 [2] 50 ac }

  condition:
    any of them
}