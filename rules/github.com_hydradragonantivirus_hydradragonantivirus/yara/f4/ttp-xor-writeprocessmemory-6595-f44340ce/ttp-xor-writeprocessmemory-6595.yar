rule TTP_XOR_WriteProcessMemory_6595 {
  strings:
    $key_6595 = { 32 e7 [2] 00 c5 [2] 06 f0 [2] 28 f0 [2] 17 ec }

  condition:
    any of them
}