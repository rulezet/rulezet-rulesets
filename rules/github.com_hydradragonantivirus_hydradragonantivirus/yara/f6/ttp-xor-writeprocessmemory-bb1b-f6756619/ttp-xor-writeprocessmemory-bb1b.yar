rule TTP_XOR_WriteProcessMemory_bb1b {
  strings:
    $key_bb1b = { ec 69 [2] de 4b [2] d8 7e [2] f6 7e [2] c9 62 }

  condition:
    any of them
}