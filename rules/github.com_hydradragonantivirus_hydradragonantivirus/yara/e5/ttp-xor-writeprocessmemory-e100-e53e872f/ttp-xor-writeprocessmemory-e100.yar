rule TTP_XOR_WriteProcessMemory_e100 {
  strings:
    $key_e100 = { b6 72 [2] 84 50 [2] 82 65 [2] ac 65 [2] 93 79 }

  condition:
    any of them
}