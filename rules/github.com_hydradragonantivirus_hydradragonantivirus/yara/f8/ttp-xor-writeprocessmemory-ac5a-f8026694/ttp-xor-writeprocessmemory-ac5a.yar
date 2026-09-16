rule TTP_XOR_WriteProcessMemory_ac5a {
  strings:
    $key_ac5a = { fb 28 [2] c9 0a [2] cf 3f [2] e1 3f [2] de 23 }

  condition:
    any of them
}