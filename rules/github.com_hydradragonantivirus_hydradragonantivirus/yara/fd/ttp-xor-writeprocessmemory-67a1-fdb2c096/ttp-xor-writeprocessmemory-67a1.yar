rule TTP_XOR_WriteProcessMemory_67a1 {
  strings:
    $key_67a1 = { 30 d3 [2] 02 f1 [2] 04 c4 [2] 2a c4 [2] 15 d8 }

  condition:
    any of them
}