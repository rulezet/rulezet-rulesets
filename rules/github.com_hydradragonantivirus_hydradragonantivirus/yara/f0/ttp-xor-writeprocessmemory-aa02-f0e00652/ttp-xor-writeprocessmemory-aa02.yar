rule TTP_XOR_WriteProcessMemory_aa02 {
  strings:
    $key_aa02 = { fd 70 [2] cf 52 [2] c9 67 [2] e7 67 [2] d8 7b }

  condition:
    any of them
}