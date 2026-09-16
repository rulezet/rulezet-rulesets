rule TTP_XOR_WriteProcessMemory_ac4f {
  strings:
    $key_ac4f = { fb 3d [2] c9 1f [2] cf 2a [2] e1 2a [2] de 36 }

  condition:
    any of them
}