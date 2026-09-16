rule TTP_XOR_WriteProcessMemory_78a7 {
  strings:
    $key_78a7 = { 2f d5 [2] 1d f7 [2] 1b c2 [2] 35 c2 [2] 0a de }

  condition:
    any of them
}