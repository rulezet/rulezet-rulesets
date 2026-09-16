rule TTP_XOR_WriteProcessMemory_ac74 {
  strings:
    $key_ac74 = { fb 06 [2] c9 24 [2] cf 11 [2] e1 11 [2] de 0d }

  condition:
    any of them
}