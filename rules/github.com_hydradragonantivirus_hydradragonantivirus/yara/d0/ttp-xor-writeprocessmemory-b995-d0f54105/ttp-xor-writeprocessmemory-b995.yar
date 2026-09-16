rule TTP_XOR_WriteProcessMemory_b995 {
  strings:
    $key_b995 = { ee e7 [2] dc c5 [2] da f0 [2] f4 f0 [2] cb ec }

  condition:
    any of them
}