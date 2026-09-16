rule TTP_XOR_WriteProcessMemory_aad7 {
  strings:
    $key_aad7 = { fd a5 [2] cf 87 [2] c9 b2 [2] e7 b2 [2] d8 ae }

  condition:
    any of them
}