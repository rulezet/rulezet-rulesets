rule TTP_XOR_WriteProcessMemory_bb71 {
  strings:
    $key_bb71 = { ec 03 [2] de 21 [2] d8 14 [2] f6 14 [2] c9 08 }

  condition:
    any of them
}