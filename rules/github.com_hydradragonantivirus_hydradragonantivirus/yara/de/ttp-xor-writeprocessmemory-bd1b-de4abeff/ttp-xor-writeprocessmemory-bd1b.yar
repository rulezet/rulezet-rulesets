rule TTP_XOR_WriteProcessMemory_bd1b {
  strings:
    $key_bd1b = { ea 69 [2] d8 4b [2] de 7e [2] f0 7e [2] cf 62 }

  condition:
    any of them
}