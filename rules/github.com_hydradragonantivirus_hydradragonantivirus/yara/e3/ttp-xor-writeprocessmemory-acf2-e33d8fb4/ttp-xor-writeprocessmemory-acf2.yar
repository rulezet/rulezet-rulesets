rule TTP_XOR_WriteProcessMemory_acf2 {
  strings:
    $key_acf2 = { fb 80 [2] c9 a2 [2] cf 97 [2] e1 97 [2] de 8b }

  condition:
    any of them
}