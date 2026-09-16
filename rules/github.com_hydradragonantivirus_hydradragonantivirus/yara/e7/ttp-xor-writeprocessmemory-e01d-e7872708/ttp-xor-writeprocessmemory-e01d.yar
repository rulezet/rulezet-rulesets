rule TTP_XOR_WriteProcessMemory_e01d {
  strings:
    $key_e01d = { b7 6f [2] 85 4d [2] 83 78 [2] ad 78 [2] 92 64 }

  condition:
    any of them
}