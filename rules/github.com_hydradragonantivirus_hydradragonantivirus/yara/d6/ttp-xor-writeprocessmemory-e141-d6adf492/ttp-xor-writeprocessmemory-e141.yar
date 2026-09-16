rule TTP_XOR_WriteProcessMemory_e141 {
  strings:
    $key_e141 = { b6 33 [2] 84 11 [2] 82 24 [2] ac 24 [2] 93 38 }

  condition:
    any of them
}