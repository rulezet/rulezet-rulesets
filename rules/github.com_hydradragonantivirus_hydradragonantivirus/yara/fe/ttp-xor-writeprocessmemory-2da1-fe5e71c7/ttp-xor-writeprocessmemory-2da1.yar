rule TTP_XOR_WriteProcessMemory_2da1 {
  strings:
    $key_2da1 = { 7a d3 [2] 48 f1 [2] 4e c4 [2] 60 c4 [2] 5f d8 }

  condition:
    any of them
}