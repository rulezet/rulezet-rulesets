rule TTP_XOR_WriteProcessMemory_acff {
  strings:
    $key_acff = { fb 8d [2] c9 af [2] cf 9a [2] e1 9a [2] de 86 }

  condition:
    any of them
}