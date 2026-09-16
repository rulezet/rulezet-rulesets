rule TTP_XOR_WriteProcessMemory_1795 {
  strings:
    $key_1795 = { 40 e7 [2] 72 c5 [2] 74 f0 [2] 5a f0 [2] 65 ec }

  condition:
    any of them
}