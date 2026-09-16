rule TTP_XOR_WriteProcessMemory_ac12 {
  strings:
    $key_ac12 = { fb 60 [2] c9 42 [2] cf 77 [2] e1 77 [2] de 6b }

  condition:
    any of them
}