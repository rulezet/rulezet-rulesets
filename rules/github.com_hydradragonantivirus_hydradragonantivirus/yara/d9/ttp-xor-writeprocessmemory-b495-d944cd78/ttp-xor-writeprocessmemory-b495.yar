rule TTP_XOR_WriteProcessMemory_b495 {
  strings:
    $key_b495 = { e3 e7 [2] d1 c5 [2] d7 f0 [2] f9 f0 [2] c6 ec }

  condition:
    any of them
}