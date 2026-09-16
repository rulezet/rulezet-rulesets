rule TTP_XOR_WriteProcessMemory_e174 {
  strings:
    $key_e174 = { b6 06 [2] 84 24 [2] 82 11 [2] ac 11 [2] 93 0d }

  condition:
    any of them
}