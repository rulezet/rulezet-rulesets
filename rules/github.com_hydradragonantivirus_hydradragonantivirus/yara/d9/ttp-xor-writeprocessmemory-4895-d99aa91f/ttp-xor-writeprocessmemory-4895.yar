rule TTP_XOR_WriteProcessMemory_4895 {
  strings:
    $key_4895 = { 1f e7 [2] 2d c5 [2] 2b f0 [2] 05 f0 [2] 3a ec }

  condition:
    any of them
}