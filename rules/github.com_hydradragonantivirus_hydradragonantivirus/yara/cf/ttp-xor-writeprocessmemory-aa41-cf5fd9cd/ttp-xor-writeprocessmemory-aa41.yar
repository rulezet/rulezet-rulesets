rule TTP_XOR_WriteProcessMemory_aa41 {
  strings:
    $key_aa41 = { fd 33 [2] cf 11 [2] c9 24 [2] e7 24 [2] d8 38 }

  condition:
    any of them
}