rule TTP_XOR_WriteProcessMemory_bd6c {
  strings:
    $key_bd6c = { ea 1e [2] d8 3c [2] de 09 [2] f0 09 [2] cf 15 }

  condition:
    any of them
}