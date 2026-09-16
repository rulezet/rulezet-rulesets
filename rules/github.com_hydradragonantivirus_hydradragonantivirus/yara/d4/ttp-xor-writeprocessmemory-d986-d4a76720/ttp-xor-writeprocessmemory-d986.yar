rule TTP_XOR_WriteProcessMemory_d986 {
  strings:
    $key_d986 = { 8e f4 [2] bc d6 [2] ba e3 [2] 94 e3 [2] ab ff }

  condition:
    any of them
}