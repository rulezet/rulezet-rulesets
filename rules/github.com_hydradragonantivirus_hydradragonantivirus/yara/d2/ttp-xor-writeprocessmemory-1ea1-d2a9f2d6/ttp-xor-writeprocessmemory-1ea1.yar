rule TTP_XOR_WriteProcessMemory_1ea1 {
  strings:
    $key_1ea1 = { 49 d3 [2] 7b f1 [2] 7d c4 [2] 53 c4 [2] 6c d8 }

  condition:
    any of them
}