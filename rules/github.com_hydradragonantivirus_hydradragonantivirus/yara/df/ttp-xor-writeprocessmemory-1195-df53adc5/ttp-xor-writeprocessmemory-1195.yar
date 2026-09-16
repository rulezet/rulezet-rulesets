rule TTP_XOR_WriteProcessMemory_1195 {
  strings:
    $key_1195 = { 46 e7 [2] 74 c5 [2] 72 f0 [2] 5c f0 [2] 63 ec }

  condition:
    any of them
}