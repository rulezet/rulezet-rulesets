rule TTP_XOR_WriteProcessMemory_16a1 {
  strings:
    $key_16a1 = { 41 d3 [2] 73 f1 [2] 75 c4 [2] 5b c4 [2] 64 d8 }

  condition:
    any of them
}