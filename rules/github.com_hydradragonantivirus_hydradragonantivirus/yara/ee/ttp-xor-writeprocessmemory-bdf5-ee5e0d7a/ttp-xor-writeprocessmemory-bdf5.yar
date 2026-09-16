rule TTP_XOR_WriteProcessMemory_bdf5 {
  strings:
    $key_bdf5 = { ea 87 [2] d8 a5 [2] de 90 [2] f0 90 [2] cf 8c }

  condition:
    any of them
}