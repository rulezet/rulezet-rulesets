rule TTP_XOR_WriteProcessMemory_930e {
  strings:
    $key_930e = { c4 7c [2] f6 5e [2] f0 6b [2] de 6b [2] e1 77 }

  condition:
    any of them
}