rule TTP_XOR_WriteProcessMemory_e02d {
  strings:
    $key_e02d = { b7 5f [2] 85 7d [2] 83 48 [2] ad 48 [2] 92 54 }

  condition:
    any of them
}