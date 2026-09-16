rule TTP_XOR_WriteProcessMemory_bd3c {
  strings:
    $key_bd3c = { ea 4e [2] d8 6c [2] de 59 [2] f0 59 [2] cf 45 }

  condition:
    any of them
}