rule TTP_XOR_WriteProcessMemory_e1c0 {
  strings:
    $key_e1c0 = { b6 b2 [2] 84 90 [2] 82 a5 [2] ac a5 [2] 93 b9 }

  condition:
    any of them
}