rule TTP_XOR_WriteProcessMemory_bd68 {
  strings:
    $key_bd68 = { ea 1a [2] d8 38 [2] de 0d [2] f0 0d [2] cf 11 }

  condition:
    any of them
}