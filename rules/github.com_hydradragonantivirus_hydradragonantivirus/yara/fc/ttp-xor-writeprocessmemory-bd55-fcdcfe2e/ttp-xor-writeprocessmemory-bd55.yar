rule TTP_XOR_WriteProcessMemory_bd55 {
  strings:
    $key_bd55 = { ea 27 [2] d8 05 [2] de 30 [2] f0 30 [2] cf 2c }

  condition:
    any of them
}