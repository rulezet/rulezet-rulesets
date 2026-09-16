rule TTP_XOR_WriteProcessMemory_b417 {
  strings:
    $key_b417 = { e3 65 [2] d1 47 [2] d7 72 [2] f9 72 [2] c6 6e }

  condition:
    any of them
}