rule TTP_XOR_WriteProcessMemory_3295 {
  strings:
    $key_3295 = { 65 e7 [2] 57 c5 [2] 51 f0 [2] 7f f0 [2] 40 ec }

  condition:
    any of them
}