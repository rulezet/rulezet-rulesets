rule TTP_XOR_WriteProcessMemory_aa4c {
  strings:
    $key_aa4c = { fd 3e [2] cf 1c [2] c9 29 [2] e7 29 [2] d8 35 }

  condition:
    any of them
}