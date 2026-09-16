rule TTP_XOR_WriteProcessMemory_1995 {
  strings:
    $key_1995 = { 4e e7 [2] 7c c5 [2] 7a f0 [2] 54 f0 [2] 6b ec }

  condition:
    any of them
}