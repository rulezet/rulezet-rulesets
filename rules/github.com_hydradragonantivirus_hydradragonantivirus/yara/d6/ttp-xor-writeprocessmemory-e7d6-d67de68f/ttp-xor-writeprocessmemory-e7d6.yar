rule TTP_XOR_WriteProcessMemory_e7d6 {
  strings:
    $key_e7d6 = { b0 a4 [2] 82 86 [2] 84 b3 [2] aa b3 [2] 95 af }

  condition:
    any of them
}