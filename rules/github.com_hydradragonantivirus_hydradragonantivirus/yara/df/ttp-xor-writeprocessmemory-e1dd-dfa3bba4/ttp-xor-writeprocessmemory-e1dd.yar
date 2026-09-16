rule TTP_XOR_WriteProcessMemory_e1dd {
  strings:
    $key_e1dd = { b6 af [2] 84 8d [2] 82 b8 [2] ac b8 [2] 93 a4 }

  condition:
    any of them
}