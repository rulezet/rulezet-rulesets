rule TTP_XOR_WriteProcessMemory_db95 {
  strings:
    $key_db95 = { 8c e7 [2] be c5 [2] b8 f0 [2] 96 f0 [2] a9 ec }

  condition:
    any of them
}