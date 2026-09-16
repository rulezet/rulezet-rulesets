rule TTP_XOR_WriteProcessMemory_aa6c {
  strings:
    $key_aa6c = { fd 1e [2] cf 3c [2] c9 09 [2] e7 09 [2] d8 15 }

  condition:
    any of them
}