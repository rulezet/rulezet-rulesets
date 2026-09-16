rule TTP_XOR_WriteProcessMemory_bd4a {
  strings:
    $key_bd4a = { ea 38 [2] d8 1a [2] de 2f [2] f0 2f [2] cf 33 }

  condition:
    any of them
}