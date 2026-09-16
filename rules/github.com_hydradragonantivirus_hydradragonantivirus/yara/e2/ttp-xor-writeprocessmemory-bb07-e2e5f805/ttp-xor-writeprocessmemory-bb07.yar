rule TTP_XOR_WriteProcessMemory_bb07 {
  strings:
    $key_bb07 = { ec 75 [2] de 57 [2] d8 62 [2] f6 62 [2] c9 7e }

  condition:
    any of them
}