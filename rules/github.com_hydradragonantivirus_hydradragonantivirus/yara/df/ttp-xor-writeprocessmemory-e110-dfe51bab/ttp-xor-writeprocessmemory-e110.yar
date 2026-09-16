rule TTP_XOR_WriteProcessMemory_e110 {
  strings:
    $key_e110 = { b6 62 [2] 84 40 [2] 82 75 [2] ac 75 [2] 93 69 }

  condition:
    any of them
}