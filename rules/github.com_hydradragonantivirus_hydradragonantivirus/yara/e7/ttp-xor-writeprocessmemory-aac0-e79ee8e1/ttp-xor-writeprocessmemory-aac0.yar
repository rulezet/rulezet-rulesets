rule TTP_XOR_WriteProcessMemory_aac0 {
  strings:
    $key_aac0 = { fd b2 [2] cf 90 [2] c9 a5 [2] e7 a5 [2] d8 b9 }

  condition:
    any of them
}