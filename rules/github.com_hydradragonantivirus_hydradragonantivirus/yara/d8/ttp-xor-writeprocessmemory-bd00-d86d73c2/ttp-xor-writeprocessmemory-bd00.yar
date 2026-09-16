rule TTP_XOR_WriteProcessMemory_bd00 {
  strings:
    $key_bd00 = { ea 72 [2] d8 50 [2] de 65 [2] f0 65 [2] cf 79 }

  condition:
    any of them
}