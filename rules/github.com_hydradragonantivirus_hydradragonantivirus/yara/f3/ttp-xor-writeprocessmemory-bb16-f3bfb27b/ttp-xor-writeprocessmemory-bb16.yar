rule TTP_XOR_WriteProcessMemory_bb16 {
  strings:
    $key_bb16 = { ec 64 [2] de 46 [2] d8 73 [2] f6 73 [2] c9 6f }

  condition:
    any of them
}