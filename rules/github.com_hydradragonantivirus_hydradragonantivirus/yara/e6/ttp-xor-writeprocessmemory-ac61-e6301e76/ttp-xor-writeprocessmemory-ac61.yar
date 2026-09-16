rule TTP_XOR_WriteProcessMemory_ac61 {
  strings:
    $key_ac61 = { fb 13 [2] c9 31 [2] cf 04 [2] e1 04 [2] de 18 }

  condition:
    any of them
}