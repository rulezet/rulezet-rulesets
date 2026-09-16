rule TTP_XOR_WriteProcessMemory_acf4 {
  strings:
    $key_acf4 = { fb 86 [2] c9 a4 [2] cf 91 [2] e1 91 [2] de 8d }

  condition:
    any of them
}