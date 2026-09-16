rule TTP_XOR_WriteProcessMemory_da95 {
  strings:
    $key_da95 = { 8d e7 [2] bf c5 [2] b9 f0 [2] 97 f0 [2] a8 ec }

  condition:
    any of them
}