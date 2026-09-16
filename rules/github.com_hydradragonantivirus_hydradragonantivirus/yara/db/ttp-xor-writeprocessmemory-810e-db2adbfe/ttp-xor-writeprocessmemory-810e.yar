rule TTP_XOR_WriteProcessMemory_810e {
  strings:
    $key_810e = { d6 7c [2] e4 5e [2] e2 6b [2] cc 6b [2] f3 77 }

  condition:
    any of them
}