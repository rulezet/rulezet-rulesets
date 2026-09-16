rule TTP_XOR_WriteProcessMemory_0095 {
  strings:
    $key_0095 = { 57 e7 [2] 65 c5 [2] 63 f0 [2] 4d f0 [2] 72 ec }

  condition:
    any of them
}