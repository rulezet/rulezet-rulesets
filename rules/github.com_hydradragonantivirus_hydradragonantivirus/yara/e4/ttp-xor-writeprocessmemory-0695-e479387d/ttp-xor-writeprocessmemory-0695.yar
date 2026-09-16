rule TTP_XOR_WriteProcessMemory_0695 {
  strings:
    $key_0695 = { 51 e7 [2] 63 c5 [2] 65 f0 [2] 4b f0 [2] 74 ec }

  condition:
    any of them
}