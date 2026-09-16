rule TTP_XOR_WriteProcessMemory_aa40 {
  strings:
    $key_aa40 = { fd 32 [2] cf 10 [2] c9 25 [2] e7 25 [2] d8 39 }

  condition:
    any of them
}