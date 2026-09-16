rule TTP_XOR_WriteProcessMemory_bd63 {
  strings:
    $key_bd63 = { ea 11 [2] d8 33 [2] de 06 [2] f0 06 [2] cf 1a }

  condition:
    any of them
}