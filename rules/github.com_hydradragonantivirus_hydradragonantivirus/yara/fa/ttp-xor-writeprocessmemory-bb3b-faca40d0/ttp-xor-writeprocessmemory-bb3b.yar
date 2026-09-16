rule TTP_XOR_WriteProcessMemory_bb3b {
  strings:
    $key_bb3b = { ec 49 [2] de 6b [2] d8 5e [2] f6 5e [2] c9 42 }

  condition:
    any of them
}