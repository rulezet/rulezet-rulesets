rule TTP_XOR_WriteProcessMemory_e10e {
  strings:
    $key_e10e = { b6 7c [2] 84 5e [2] 82 6b [2] ac 6b [2] 93 77 }

  condition:
    any of them
}