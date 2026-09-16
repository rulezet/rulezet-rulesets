rule TTP_XOR_WriteProcessMemory_bb2b {
  strings:
    $key_bb2b = { ec 59 [2] de 7b [2] d8 4e [2] f6 4e [2] c9 52 }

  condition:
    any of them
}