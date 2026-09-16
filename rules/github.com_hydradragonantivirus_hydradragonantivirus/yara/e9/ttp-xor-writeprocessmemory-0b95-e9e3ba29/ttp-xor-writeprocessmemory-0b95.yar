rule TTP_XOR_WriteProcessMemory_0b95 {
  strings:
    $key_0b95 = { 5c e7 [2] 6e c5 [2] 68 f0 [2] 46 f0 [2] 79 ec }

  condition:
    any of them
}