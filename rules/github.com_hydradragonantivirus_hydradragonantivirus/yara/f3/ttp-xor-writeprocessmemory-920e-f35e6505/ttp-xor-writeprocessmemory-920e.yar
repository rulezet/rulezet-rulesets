rule TTP_XOR_WriteProcessMemory_920e {
  strings:
    $key_920e = { c5 7c [2] f7 5e [2] f1 6b [2] df 6b [2] e0 77 }

  condition:
    any of them
}