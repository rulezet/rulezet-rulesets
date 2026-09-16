rule TTP_XOR_WriteProcessMemory_ac78 {
  strings:
    $key_ac78 = { fb 0a [2] c9 28 [2] cf 1d [2] e1 1d [2] de 01 }

  condition:
    any of them
}