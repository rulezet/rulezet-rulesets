rule TTP_XOR_WriteProcessMemory_bb00 {
  strings:
    $key_bb00 = { ec 72 [2] de 50 [2] d8 65 [2] f6 65 [2] c9 79 }

  condition:
    any of them
}