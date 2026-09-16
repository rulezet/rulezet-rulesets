rule TTP_XOR_WriteProcessMemory_e012 {
  strings:
    $key_e012 = { b7 60 [2] 85 42 [2] 83 77 [2] ad 77 [2] 92 6b }

  condition:
    any of them
}