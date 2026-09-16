rule TTP_XOR_WriteProcessMemory_0da1 {
  strings:
    $key_0da1 = { 5a d3 [2] 68 f1 [2] 6e c4 [2] 40 c4 [2] 7f d8 }

  condition:
    any of them
}