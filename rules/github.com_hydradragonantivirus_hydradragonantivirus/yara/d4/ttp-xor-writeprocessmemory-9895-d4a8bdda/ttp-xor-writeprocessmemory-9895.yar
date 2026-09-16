rule TTP_XOR_WriteProcessMemory_9895 {
  strings:
    $key_9895 = { cf e7 [2] fd c5 [2] fb f0 [2] d5 f0 [2] ea ec }

  condition:
    any of them
}