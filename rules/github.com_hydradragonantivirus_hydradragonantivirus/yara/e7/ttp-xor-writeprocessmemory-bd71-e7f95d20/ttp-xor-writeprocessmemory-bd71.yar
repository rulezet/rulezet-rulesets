rule TTP_XOR_WriteProcessMemory_bd71 {
  strings:
    $key_bd71 = { ea 03 [2] d8 21 [2] de 14 [2] f0 14 [2] cf 08 }

  condition:
    any of them
}