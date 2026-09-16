rule TTP_XOR_WriteProcessMemory_e129 {
  strings:
    $key_e129 = { b6 5b [2] 84 79 [2] 82 4c [2] ac 4c [2] 93 50 }

  condition:
    any of them
}