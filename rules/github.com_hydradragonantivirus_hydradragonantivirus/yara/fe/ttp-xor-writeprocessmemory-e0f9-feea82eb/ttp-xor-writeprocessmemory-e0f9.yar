rule TTP_XOR_WriteProcessMemory_e0f9 {
  strings:
    $key_e0f9 = { b7 8b [2] 85 a9 [2] 83 9c [2] ad 9c [2] 92 80 }

  condition:
    any of them
}