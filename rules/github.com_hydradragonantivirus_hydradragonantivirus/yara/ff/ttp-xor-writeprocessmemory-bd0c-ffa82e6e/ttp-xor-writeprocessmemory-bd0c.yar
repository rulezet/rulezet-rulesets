rule TTP_XOR_WriteProcessMemory_bd0c {
  strings:
    $key_bd0c = { ea 7e [2] d8 5c [2] de 69 [2] f0 69 [2] cf 75 }

  condition:
    any of them
}