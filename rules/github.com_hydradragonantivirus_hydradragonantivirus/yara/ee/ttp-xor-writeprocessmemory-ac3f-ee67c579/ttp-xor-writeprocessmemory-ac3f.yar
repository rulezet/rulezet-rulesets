rule TTP_XOR_WriteProcessMemory_ac3f {
  strings:
    $key_ac3f = { fb 4d [2] c9 6f [2] cf 5a [2] e1 5a [2] de 46 }

  condition:
    any of them
}