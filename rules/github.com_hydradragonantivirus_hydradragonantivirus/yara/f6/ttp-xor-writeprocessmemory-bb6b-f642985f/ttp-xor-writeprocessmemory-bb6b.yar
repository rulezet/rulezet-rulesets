rule TTP_XOR_WriteProcessMemory_bb6b {
  strings:
    $key_bb6b = { ec 19 [2] de 3b [2] d8 0e [2] f6 0e [2] c9 12 }

  condition:
    any of them
}