rule TTP_XOR_WriteProcessMemory_bb42 {
  strings:
    $key_bb42 = { ec 30 [2] de 12 [2] d8 27 [2] f6 27 [2] c9 3b }

  condition:
    any of them
}