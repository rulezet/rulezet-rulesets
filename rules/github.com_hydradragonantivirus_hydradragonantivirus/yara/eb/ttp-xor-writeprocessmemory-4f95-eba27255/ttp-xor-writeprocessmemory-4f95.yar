rule TTP_XOR_WriteProcessMemory_4f95 {
  strings:
    $key_4f95 = { 18 e7 [2] 2a c5 [2] 2c f0 [2] 02 f0 [2] 3d ec }

  condition:
    any of them
}