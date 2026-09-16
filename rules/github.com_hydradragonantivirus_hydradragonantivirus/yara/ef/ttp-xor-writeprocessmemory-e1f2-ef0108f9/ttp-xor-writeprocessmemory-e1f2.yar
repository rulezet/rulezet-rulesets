rule TTP_XOR_WriteProcessMemory_e1f2 {
  strings:
    $key_e1f2 = { b6 80 [2] 84 a2 [2] 82 97 [2] ac 97 [2] 93 8b }

  condition:
    any of them
}