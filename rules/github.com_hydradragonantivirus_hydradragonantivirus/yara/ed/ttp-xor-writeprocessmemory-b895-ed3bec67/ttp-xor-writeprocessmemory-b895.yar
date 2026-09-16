rule TTP_XOR_WriteProcessMemory_b895 {
  strings:
    $key_b895 = { ef e7 [2] dd c5 [2] db f0 [2] f5 f0 [2] ca ec }

  condition:
    any of them
}