rule TTP_XOR_WriteProcessMemory_aac4 {
  strings:
    $key_aac4 = { fd b6 [2] cf 94 [2] c9 a1 [2] e7 a1 [2] d8 bd }

  condition:
    any of them
}