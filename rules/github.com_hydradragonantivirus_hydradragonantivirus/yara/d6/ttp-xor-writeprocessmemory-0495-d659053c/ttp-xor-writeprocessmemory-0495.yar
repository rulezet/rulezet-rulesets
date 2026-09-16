rule TTP_XOR_WriteProcessMemory_0495 {
  strings:
    $key_0495 = { 53 e7 [2] 61 c5 [2] 67 f0 [2] 49 f0 [2] 76 ec }

  condition:
    any of them
}