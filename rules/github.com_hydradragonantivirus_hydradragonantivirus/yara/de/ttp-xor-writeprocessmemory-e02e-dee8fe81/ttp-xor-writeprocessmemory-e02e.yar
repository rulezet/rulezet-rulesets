rule TTP_XOR_WriteProcessMemory_e02e {
  strings:
    $key_e02e = { b7 5c [2] 85 7e [2] 83 4b [2] ad 4b [2] 92 57 }

  condition:
    any of them
}