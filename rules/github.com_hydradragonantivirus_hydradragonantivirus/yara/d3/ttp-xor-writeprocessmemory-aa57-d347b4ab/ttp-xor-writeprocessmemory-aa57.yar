rule TTP_XOR_WriteProcessMemory_aa57 {
  strings:
    $key_aa57 = { fd 25 [2] cf 07 [2] c9 32 [2] e7 32 [2] d8 2e }

  condition:
    any of them
}