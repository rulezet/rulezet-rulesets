rule TTP_XOR_WriteProcessMemory_e13e {
  strings:
    $key_e13e = { b6 4c [2] 84 6e [2] 82 5b [2] ac 5b [2] 93 47 }

  condition:
    any of them
}