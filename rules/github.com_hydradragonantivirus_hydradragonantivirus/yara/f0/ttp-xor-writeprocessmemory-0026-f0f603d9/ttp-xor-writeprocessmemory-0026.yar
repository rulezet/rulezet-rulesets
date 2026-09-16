rule TTP_XOR_WriteProcessMemory_0026 {
  strings:
    $key_0026 = { 57 54 [2] 65 76 [2] 63 43 [2] 4d 43 [2] 72 5f }

  condition:
    any of them
}