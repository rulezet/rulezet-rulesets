rule TTP_XOR_WriteProcessMemory_aa53 {
  strings:
    $key_aa53 = { fd 21 [2] cf 03 [2] c9 36 [2] e7 36 [2] d8 2a }

  condition:
    any of them
}