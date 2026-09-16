rule TTP_XOR_WriteProcessMemory_bb3e {
  strings:
    $key_bb3e = { ec 4c [2] de 6e [2] d8 5b [2] f6 5b [2] c9 47 }

  condition:
    any of them
}