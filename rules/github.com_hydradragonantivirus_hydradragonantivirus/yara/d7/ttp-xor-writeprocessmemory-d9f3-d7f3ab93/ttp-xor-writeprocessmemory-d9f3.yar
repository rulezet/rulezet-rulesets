rule TTP_XOR_WriteProcessMemory_d9f3 {
  strings:
    $key_d9f3 = { 8e 81 [2] bc a3 [2] ba 96 [2] 94 96 [2] ab 8a }

  condition:
    any of them
}