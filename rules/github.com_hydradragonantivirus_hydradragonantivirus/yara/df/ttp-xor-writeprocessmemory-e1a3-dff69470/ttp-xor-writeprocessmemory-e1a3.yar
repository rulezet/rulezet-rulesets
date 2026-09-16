rule TTP_XOR_WriteProcessMemory_e1a3 {
  strings:
    $key_e1a3 = { b6 d1 [2] 84 f3 [2] 82 c6 [2] ac c6 [2] 93 da }

  condition:
    any of them
}