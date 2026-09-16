rule TTP_XOR_WriteProcessMemory_0895 {
  strings:
    $key_0895 = { 5f e7 [2] 6d c5 [2] 6b f0 [2] 45 f0 [2] 7a ec }

  condition:
    any of them
}