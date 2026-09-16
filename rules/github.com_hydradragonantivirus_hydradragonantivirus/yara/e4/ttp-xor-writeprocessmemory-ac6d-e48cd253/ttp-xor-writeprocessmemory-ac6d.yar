rule TTP_XOR_WriteProcessMemory_ac6d {
  strings:
    $key_ac6d = { fb 1f [2] c9 3d [2] cf 08 [2] e1 08 [2] de 14 }

  condition:
    any of them
}