rule TTP_XOR_WriteProcessMemory_ac57 {
  strings:
    $key_ac57 = { fb 25 [2] c9 07 [2] cf 32 [2] e1 32 [2] de 2e }

  condition:
    any of them
}