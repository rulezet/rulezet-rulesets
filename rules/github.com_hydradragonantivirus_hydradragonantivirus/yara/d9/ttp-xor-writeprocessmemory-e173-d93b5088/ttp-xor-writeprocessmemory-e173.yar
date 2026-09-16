rule TTP_XOR_WriteProcessMemory_e173 {
  strings:
    $key_e173 = { b6 01 [2] 84 23 [2] 82 16 [2] ac 16 [2] 93 0a }

  condition:
    any of them
}