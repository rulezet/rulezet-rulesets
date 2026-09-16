rule TTP_XOR_WriteProcessMemory_a495 {
  strings:
    $key_a495 = { f3 e7 [2] c1 c5 [2] c7 f0 [2] e9 f0 [2] d6 ec }

  condition:
    any of them
}