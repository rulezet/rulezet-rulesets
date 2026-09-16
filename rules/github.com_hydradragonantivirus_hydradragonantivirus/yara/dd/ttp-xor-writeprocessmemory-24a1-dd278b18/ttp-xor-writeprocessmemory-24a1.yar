rule TTP_XOR_WriteProcessMemory_24a1 {
  strings:
    $key_24a1 = { 73 d3 [2] 41 f1 [2] 47 c4 [2] 69 c4 [2] 56 d8 }

  condition:
    any of them
}