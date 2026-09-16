rule TTP_XOR_WriteProcessMemory_bdd7 {
  strings:
    $key_bdd7 = { ea a5 [2] d8 87 [2] de b2 [2] f0 b2 [2] cf ae }

  condition:
    any of them
}