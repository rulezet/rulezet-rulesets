rule TTP_XOR_WriteProcessMemory_d9f9 {
  strings:
    $key_d9f9 = { 8e 8b [2] bc a9 [2] ba 9c [2] 94 9c [2] ab 80 }

  condition:
    any of them
}