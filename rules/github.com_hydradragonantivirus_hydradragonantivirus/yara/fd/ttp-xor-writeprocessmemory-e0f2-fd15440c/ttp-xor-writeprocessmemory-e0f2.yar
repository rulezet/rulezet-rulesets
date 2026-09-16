rule TTP_XOR_WriteProcessMemory_e0f2 {
  strings:
    $key_e0f2 = { b7 80 [2] 85 a2 [2] 83 97 [2] ad 97 [2] 92 8b }

  condition:
    any of them
}