rule TTP_XOR_WriteProcessMemory_bd60 {
  strings:
    $key_bd60 = { ea 12 [2] d8 30 [2] de 05 [2] f0 05 [2] cf 19 }

  condition:
    any of them
}