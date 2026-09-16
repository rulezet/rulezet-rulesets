rule TTP_XOR_WriteProcessMemory_bb26 {
  strings:
    $key_bb26 = { ec 54 [2] de 76 [2] d8 43 [2] f6 43 [2] c9 5f }

  condition:
    any of them
}