rule TTP_XOR_WriteProcessMemory_bde2 {
  strings:
    $key_bde2 = { ea 90 [2] d8 b2 [2] de 87 [2] f0 87 [2] cf 9b }

  condition:
    any of them
}