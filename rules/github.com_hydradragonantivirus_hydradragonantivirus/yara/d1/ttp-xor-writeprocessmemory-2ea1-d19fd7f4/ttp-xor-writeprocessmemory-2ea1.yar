rule TTP_XOR_WriteProcessMemory_2ea1 {
  strings:
    $key_2ea1 = { 79 d3 [2] 4b f1 [2] 4d c4 [2] 63 c4 [2] 5c d8 }

  condition:
    any of them
}