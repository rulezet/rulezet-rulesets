rule TTP_XOR_WriteProcessMemory_e0f1 {
  strings:
    $key_e0f1 = { b7 83 [2] 85 a1 [2] 83 94 [2] ad 94 [2] 92 88 }

  condition:
    any of them
}