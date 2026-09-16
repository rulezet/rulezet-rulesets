rule TTP_XOR_WriteProcessMemory_bb40 {
  strings:
    $key_bb40 = { ec 32 [2] de 10 [2] d8 25 [2] f6 25 [2] c9 39 }

  condition:
    any of them
}