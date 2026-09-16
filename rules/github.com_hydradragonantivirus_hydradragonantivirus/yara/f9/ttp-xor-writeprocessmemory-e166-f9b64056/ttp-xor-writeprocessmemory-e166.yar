rule TTP_XOR_WriteProcessMemory_e166 {
  strings:
    $key_e166 = { b6 14 [2] 84 36 [2] 82 03 [2] ac 03 [2] 93 1f }

  condition:
    any of them
}