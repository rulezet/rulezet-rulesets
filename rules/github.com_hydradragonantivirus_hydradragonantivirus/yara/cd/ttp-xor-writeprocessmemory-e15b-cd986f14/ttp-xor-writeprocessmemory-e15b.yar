rule TTP_XOR_WriteProcessMemory_e15b {
  strings:
    $key_e15b = { b6 29 [2] 84 0b [2] 82 3e [2] ac 3e [2] 93 22 }

  condition:
    any of them
}