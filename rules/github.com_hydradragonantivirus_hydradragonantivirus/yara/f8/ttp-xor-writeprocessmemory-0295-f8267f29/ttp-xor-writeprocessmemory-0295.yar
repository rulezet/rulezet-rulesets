rule TTP_XOR_WriteProcessMemory_0295 {
  strings:
    $key_0295 = { 55 e7 [2] 67 c5 [2] 61 f0 [2] 4f f0 [2] 70 ec }

  condition:
    any of them
}