rule TTP_XOR_WriteProcessMemory_2da0 {
  strings:
    $key_2da0 = { 7a d2 [2] 48 f0 [2] 4e c5 [2] 60 c5 [2] 5f d9 }

  condition:
    any of them
}