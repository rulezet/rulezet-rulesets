rule TTP_XOR_WriteProcessMemory_ac07 {
  strings:
    $key_ac07 = { fb 75 [2] c9 57 [2] cf 62 [2] e1 62 [2] de 7e }

  condition:
    any of them
}