rule TTP_XOR_WriteProcessMemory_d995 {
  strings:
    $key_d995 = { 8e e7 [2] bc c5 [2] ba f0 [2] 94 f0 [2] ab ec }

  condition:
    any of them
}