rule TTP_XOR_WriteProcessMemory_bbd4 {
  strings:
    $key_bbd4 = { ec a6 [2] de 84 [2] d8 b1 [2] f6 b1 [2] c9 ad }

  condition:
    any of them
}