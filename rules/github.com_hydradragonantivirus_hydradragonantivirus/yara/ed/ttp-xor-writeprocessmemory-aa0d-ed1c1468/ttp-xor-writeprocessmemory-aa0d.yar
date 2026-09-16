rule TTP_XOR_WriteProcessMemory_aa0d {
  strings:
    $key_aa0d = { fd 7f [2] cf 5d [2] c9 68 [2] e7 68 [2] d8 74 }

  condition:
    any of them
}