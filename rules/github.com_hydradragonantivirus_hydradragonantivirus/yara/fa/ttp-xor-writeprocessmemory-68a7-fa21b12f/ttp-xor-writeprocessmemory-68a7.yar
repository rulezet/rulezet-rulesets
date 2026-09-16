rule TTP_XOR_WriteProcessMemory_68a7 {
  strings:
    $key_68a7 = { 3f d5 [2] 0d f7 [2] 0b c2 [2] 25 c2 [2] 1a de }

  condition:
    any of them
}