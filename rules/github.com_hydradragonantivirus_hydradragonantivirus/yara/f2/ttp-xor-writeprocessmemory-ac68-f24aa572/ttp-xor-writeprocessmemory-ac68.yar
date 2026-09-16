rule TTP_XOR_WriteProcessMemory_ac68 {
  strings:
    $key_ac68 = { fb 1a [2] c9 38 [2] cf 0d [2] e1 0d [2] de 11 }

  condition:
    any of them
}