rule TTP_XOR_WriteProcessMemory_9095 {
  strings:
    $key_9095 = { c7 e7 [2] f5 c5 [2] f3 f0 [2] dd f0 [2] e2 ec }

  condition:
    any of them
}