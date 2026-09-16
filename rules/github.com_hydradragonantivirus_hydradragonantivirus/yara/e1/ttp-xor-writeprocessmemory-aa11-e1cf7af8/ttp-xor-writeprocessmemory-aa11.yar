rule TTP_XOR_WriteProcessMemory_aa11 {
  strings:
    $key_aa11 = { fd 63 [2] cf 41 [2] c9 74 [2] e7 74 [2] d8 68 }

  condition:
    any of them
}