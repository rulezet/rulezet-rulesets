rule TTP_XOR_WriteProcessMemory_ac22 {
  strings:
    $key_ac22 = { fb 50 [2] c9 72 [2] cf 47 [2] e1 47 [2] de 5b }

  condition:
    any of them
}