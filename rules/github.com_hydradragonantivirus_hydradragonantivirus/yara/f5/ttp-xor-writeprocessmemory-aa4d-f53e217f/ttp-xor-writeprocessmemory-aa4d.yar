rule TTP_XOR_WriteProcessMemory_aa4d {
  strings:
    $key_aa4d = { fd 3f [2] cf 1d [2] c9 28 [2] e7 28 [2] d8 34 }

  condition:
    any of them
}