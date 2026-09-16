rule TTP_XOR_WriteProcessMemory_8267 {
  strings:
    $key_8267 = { d5 15 [2] e7 37 [2] e1 02 [2] cf 02 [2] f0 1e }

  condition:
    any of them
}