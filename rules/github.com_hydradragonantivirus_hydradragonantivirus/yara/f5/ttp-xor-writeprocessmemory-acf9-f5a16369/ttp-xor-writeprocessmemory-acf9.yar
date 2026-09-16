rule TTP_XOR_WriteProcessMemory_acf9 {
  strings:
    $key_acf9 = { fb 8b [2] c9 a9 [2] cf 9c [2] e1 9c [2] de 80 }

  condition:
    any of them
}