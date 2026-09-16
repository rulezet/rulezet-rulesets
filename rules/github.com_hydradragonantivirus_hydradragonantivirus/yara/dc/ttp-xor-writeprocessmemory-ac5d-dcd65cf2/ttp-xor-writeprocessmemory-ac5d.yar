rule TTP_XOR_WriteProcessMemory_ac5d {
  strings:
    $key_ac5d = { fb 2f [2] c9 0d [2] cf 38 [2] e1 38 [2] de 24 }

  condition:
    any of them
}