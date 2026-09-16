rule TTP_XOR_WriteProcessMemory_bb56 {
  strings:
    $key_bb56 = { ec 24 [2] de 06 [2] d8 33 [2] f6 33 [2] c9 2f }

  condition:
    any of them
}