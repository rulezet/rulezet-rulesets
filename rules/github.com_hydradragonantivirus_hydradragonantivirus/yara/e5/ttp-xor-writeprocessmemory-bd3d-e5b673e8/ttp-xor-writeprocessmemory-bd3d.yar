rule TTP_XOR_WriteProcessMemory_bd3d {
  strings:
    $key_bd3d = { ea 4f [2] d8 6d [2] de 58 [2] f0 58 [2] cf 44 }

  condition:
    any of them
}