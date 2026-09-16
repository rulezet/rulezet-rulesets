rule TTP_XOR_WriteProcessMemory_acf3 {
  strings:
    $key_acf3 = { fb 81 [2] c9 a3 [2] cf 96 [2] e1 96 [2] de 8a }

  condition:
    any of them
}