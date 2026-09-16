rule TTP_XOR_WriteProcessMemory_813b {
  strings:
    $key_813b = { d6 49 [2] e4 6b [2] e2 5e [2] cc 5e [2] f3 42 }

  condition:
    any of them
}