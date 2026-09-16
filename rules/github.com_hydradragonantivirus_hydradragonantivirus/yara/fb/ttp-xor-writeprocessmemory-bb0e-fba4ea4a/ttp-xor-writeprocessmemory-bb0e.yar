rule TTP_XOR_WriteProcessMemory_bb0e {
  strings:
    $key_bb0e = { ec 7c [2] de 5e [2] d8 6b [2] f6 6b [2] c9 77 }

  condition:
    any of them
}