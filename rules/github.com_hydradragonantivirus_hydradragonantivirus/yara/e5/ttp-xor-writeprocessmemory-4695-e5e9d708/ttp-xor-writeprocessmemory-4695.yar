rule TTP_XOR_WriteProcessMemory_4695 {
  strings:
    $key_4695 = { 11 e7 [2] 23 c5 [2] 25 f0 [2] 0b f0 [2] 34 ec }

  condition:
    any of them
}