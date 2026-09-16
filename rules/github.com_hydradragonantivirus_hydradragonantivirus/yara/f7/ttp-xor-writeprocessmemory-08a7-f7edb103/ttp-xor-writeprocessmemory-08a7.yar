rule TTP_XOR_WriteProcessMemory_08a7 {
  strings:
    $key_08a7 = { 5f d5 [2] 6d f7 [2] 6b c2 [2] 45 c2 [2] 7a de }

  condition:
    any of them
}