rule TTP_XOR_WriteProcessMemory_e1e6 {
  strings:
    $key_e1e6 = { b6 94 [2] 84 b6 [2] 82 83 [2] ac 83 [2] 93 9f }

  condition:
    any of them
}