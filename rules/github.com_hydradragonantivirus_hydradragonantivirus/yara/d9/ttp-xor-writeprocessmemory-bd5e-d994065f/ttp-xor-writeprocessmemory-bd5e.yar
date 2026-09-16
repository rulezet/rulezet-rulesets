rule TTP_XOR_WriteProcessMemory_bd5e {
  strings:
    $key_bd5e = { ea 2c [2] d8 0e [2] de 3b [2] f0 3b [2] cf 27 }

  condition:
    any of them
}