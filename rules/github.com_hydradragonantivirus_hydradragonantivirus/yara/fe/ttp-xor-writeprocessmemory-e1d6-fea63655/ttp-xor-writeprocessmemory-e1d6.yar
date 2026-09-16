rule TTP_XOR_WriteProcessMemory_e1d6 {
  strings:
    $key_e1d6 = { b6 a4 [2] 84 86 [2] 82 b3 [2] ac b3 [2] 93 af }

  condition:
    any of them
}