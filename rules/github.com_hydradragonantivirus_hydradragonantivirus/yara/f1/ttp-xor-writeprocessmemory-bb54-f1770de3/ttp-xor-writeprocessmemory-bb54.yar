rule TTP_XOR_WriteProcessMemory_bb54 {
  strings:
    $key_bb54 = { ec 26 [2] de 04 [2] d8 31 [2] f6 31 [2] c9 2d }

  condition:
    any of them
}