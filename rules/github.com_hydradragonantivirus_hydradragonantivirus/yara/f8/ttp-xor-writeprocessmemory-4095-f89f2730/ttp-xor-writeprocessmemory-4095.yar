rule TTP_XOR_WriteProcessMemory_4095 {
  strings:
    $key_4095 = { 17 e7 [2] 25 c5 [2] 23 f0 [2] 0d f0 [2] 32 ec }

  condition:
    any of them
}