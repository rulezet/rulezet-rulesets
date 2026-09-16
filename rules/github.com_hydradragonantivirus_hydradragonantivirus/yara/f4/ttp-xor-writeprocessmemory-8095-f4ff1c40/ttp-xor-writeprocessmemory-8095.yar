rule TTP_XOR_WriteProcessMemory_8095 {
  strings:
    $key_8095 = { d7 e7 [2] e5 c5 [2] e3 f0 [2] cd f0 [2] f2 ec }

  condition:
    any of them
}