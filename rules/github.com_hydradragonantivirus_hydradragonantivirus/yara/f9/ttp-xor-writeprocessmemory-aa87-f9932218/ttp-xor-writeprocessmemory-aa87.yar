rule TTP_XOR_WriteProcessMemory_aa87 {
  strings:
    $key_aa87 = { fd f5 [2] cf d7 [2] c9 e2 [2] e7 e2 [2] d8 fe }

  condition:
    any of them
}