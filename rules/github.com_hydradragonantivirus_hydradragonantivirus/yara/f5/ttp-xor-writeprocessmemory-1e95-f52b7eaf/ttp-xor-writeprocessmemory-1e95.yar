rule TTP_XOR_WriteProcessMemory_1e95 {
  strings:
    $key_1e95 = { 49 e7 [2] 7b c5 [2] 7d f0 [2] 53 f0 [2] 6c ec }

  condition:
    any of them
}