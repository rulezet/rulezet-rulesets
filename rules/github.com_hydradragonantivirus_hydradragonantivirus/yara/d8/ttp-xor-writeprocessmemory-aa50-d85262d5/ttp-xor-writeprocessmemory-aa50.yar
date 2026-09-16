rule TTP_XOR_WriteProcessMemory_aa50 {
  strings:
    $key_aa50 = { fd 22 [2] cf 00 [2] c9 35 [2] e7 35 [2] d8 29 }

  condition:
    any of them
}