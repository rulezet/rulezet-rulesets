rule TTP_XOR_WriteProcessMemory_d9a2 {
  strings:
    $key_d9a2 = { 8e d0 [2] bc f2 [2] ba c7 [2] 94 c7 [2] ab db }

  condition:
    any of them
}