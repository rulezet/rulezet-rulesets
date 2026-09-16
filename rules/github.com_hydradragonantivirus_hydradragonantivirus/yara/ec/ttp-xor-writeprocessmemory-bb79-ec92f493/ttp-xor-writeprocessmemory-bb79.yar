rule TTP_XOR_WriteProcessMemory_bb79 {
  strings:
    $key_bb79 = { ec 0b [2] de 29 [2] d8 1c [2] f6 1c [2] c9 00 }

  condition:
    any of them
}