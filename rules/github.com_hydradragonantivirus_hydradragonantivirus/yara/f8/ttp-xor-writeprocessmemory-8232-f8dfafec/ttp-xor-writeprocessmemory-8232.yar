rule TTP_XOR_WriteProcessMemory_8232 {
  strings:
    $key_8232 = { d5 40 [2] e7 62 [2] e1 57 [2] cf 57 [2] f0 4b }

  condition:
    any of them
}