rule TTP_XOR_WriteProcessMemory_e130 {
  strings:
    $key_e130 = { b6 42 [2] 84 60 [2] 82 55 [2] ac 55 [2] 93 49 }

  condition:
    any of them
}