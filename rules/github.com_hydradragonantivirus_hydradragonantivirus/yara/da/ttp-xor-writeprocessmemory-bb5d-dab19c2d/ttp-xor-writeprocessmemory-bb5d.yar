rule TTP_XOR_WriteProcessMemory_bb5d {
  strings:
    $key_bb5d = { ec 2f [2] de 0d [2] d8 38 [2] f6 38 [2] c9 24 }

  condition:
    any of them
}