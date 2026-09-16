rule TTP_XOR_WriteProcessMemory_aa5d {
  strings:
    $key_aa5d = { fd 2f [2] cf 0d [2] c9 38 [2] e7 38 [2] d8 24 }

  condition:
    any of them
}