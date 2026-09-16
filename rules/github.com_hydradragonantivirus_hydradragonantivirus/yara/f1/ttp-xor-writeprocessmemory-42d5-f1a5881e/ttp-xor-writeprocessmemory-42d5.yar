rule TTP_XOR_WriteProcessMemory_42d5 {
  strings:
    $key_42d5 = { 15 a7 [2] 27 85 [2] 21 b0 [2] 0f b0 [2] 30 ac }

  condition:
    any of them
}