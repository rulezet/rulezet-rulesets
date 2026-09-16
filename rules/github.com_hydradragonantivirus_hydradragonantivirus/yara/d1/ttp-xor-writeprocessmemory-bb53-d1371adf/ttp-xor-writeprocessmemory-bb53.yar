rule TTP_XOR_WriteProcessMemory_bb53 {
  strings:
    $key_bb53 = { ec 21 [2] de 03 [2] d8 36 [2] f6 36 [2] c9 2a }

  condition:
    any of them
}