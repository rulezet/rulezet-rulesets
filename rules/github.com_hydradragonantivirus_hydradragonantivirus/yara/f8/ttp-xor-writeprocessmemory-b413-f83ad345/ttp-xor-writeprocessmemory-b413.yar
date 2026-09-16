rule TTP_XOR_WriteProcessMemory_b413 {
  strings:
    $key_b413 = { e3 61 [2] d1 43 [2] d7 76 [2] f9 76 [2] c6 6a }

  condition:
    any of them
}