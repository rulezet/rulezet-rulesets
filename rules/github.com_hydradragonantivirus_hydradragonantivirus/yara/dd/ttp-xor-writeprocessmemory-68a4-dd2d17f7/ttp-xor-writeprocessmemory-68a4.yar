rule TTP_XOR_WriteProcessMemory_68a4 {
  strings:
    $key_68a4 = { 3f d6 [2] 0d f4 [2] 0b c1 [2] 25 c1 [2] 1a dd }

  condition:
    any of them
}