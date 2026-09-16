rule TTP_XOR_WriteProcessMemory_bd20 {
  strings:
    $key_bd20 = { ea 52 [2] d8 70 [2] de 45 [2] f0 45 [2] cf 59 }

  condition:
    any of them
}