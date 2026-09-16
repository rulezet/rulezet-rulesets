rule TTP_XOR_WriteProcessMemory_e1e8 {
  strings:
    $key_e1e8 = { b6 9a [2] 84 b8 [2] 82 8d [2] ac 8d [2] 93 91 }

  condition:
    any of them
}