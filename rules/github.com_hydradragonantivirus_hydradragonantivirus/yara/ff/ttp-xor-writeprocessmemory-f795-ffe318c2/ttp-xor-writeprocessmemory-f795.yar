rule TTP_XOR_WriteProcessMemory_f795 {
  strings:
    $key_f795 = { a0 e7 [2] 92 c5 [2] 94 f0 [2] ba f0 [2] 85 ec }

  condition:
    any of them
}