rule TTP_XOR_WriteProcessMemory_8277 {
  strings:
    $key_8277 = { d5 05 [2] e7 27 [2] e1 12 [2] cf 12 [2] f0 0e }

  condition:
    any of them
}