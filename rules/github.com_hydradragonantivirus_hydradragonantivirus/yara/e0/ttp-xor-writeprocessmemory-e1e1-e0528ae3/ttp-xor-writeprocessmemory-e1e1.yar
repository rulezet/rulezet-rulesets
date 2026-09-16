rule TTP_XOR_WriteProcessMemory_e1e1 {
  strings:
    $key_e1e1 = { b6 93 [2] 84 b1 [2] 82 84 [2] ac 84 [2] 93 98 }

  condition:
    any of them
}