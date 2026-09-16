rule TTP_XOR_WriteProcessMemory_d9f2 {
  strings:
    $key_d9f2 = { 8e 80 [2] bc a2 [2] ba 97 [2] 94 97 [2] ab 8b }

  condition:
    any of them
}