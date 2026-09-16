rule TTP_XOR_WriteProcessMemory_12d5 {
  strings:
    $key_12d5 = { 45 a7 [2] 77 85 [2] 71 b0 [2] 5f b0 [2] 60 ac }

  condition:
    any of them
}