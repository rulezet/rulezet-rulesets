rule TTP_XOR_WriteProcessMemory_e025 {
  strings:
    $key_e025 = { b7 57 [2] 85 75 [2] 83 40 [2] ad 40 [2] 92 5c }

  condition:
    any of them
}