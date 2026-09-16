rule TTP_XOR_WriteProcessMemory_1b95 {
  strings:
    $key_1b95 = { 4c e7 [2] 7e c5 [2] 78 f0 [2] 56 f0 [2] 69 ec }

  condition:
    any of them
}