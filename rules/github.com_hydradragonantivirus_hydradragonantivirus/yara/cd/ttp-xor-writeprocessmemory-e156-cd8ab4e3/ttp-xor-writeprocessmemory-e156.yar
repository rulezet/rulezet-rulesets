rule TTP_XOR_WriteProcessMemory_e156 {
  strings:
    $key_e156 = { b6 24 [2] 84 06 [2] 82 33 [2] ac 33 [2] 93 2f }

  condition:
    any of them
}