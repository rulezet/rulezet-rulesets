rule TTP_XOR_WriteProcessMemory_bb70 {
  strings:
    $key_bb70 = { ec 02 [2] de 20 [2] d8 15 [2] f6 15 [2] c9 09 }

  condition:
    any of them
}