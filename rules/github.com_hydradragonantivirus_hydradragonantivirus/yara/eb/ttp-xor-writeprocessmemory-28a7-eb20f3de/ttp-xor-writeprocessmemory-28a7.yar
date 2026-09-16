rule TTP_XOR_WriteProcessMemory_28a7 {
  strings:
    $key_28a7 = { 7f d5 [2] 4d f7 [2] 4b c2 [2] 65 c2 [2] 5a de }

  condition:
    any of them
}