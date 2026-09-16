rule TTP_XOR_WriteProcessMemory_e1f9 {
  strings:
    $key_e1f9 = { b6 8b [2] 84 a9 [2] 82 9c [2] ac 9c [2] 93 80 }

  condition:
    any of them
}