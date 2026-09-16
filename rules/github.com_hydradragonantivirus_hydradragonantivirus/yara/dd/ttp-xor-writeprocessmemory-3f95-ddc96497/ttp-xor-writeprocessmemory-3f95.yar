rule TTP_XOR_WriteProcessMemory_3f95 {
  strings:
    $key_3f95 = { 68 e7 [2] 5a c5 [2] 5c f0 [2] 72 f0 [2] 4d ec }

  condition:
    any of them
}