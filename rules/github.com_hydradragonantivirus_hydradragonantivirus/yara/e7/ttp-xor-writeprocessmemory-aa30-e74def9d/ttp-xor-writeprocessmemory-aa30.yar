rule TTP_XOR_WriteProcessMemory_aa30 {
  strings:
    $key_aa30 = { fd 42 [2] cf 60 [2] c9 55 [2] e7 55 [2] d8 49 }

  condition:
    any of them
}