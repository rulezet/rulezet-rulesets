rule TTP_XOR_WriteProcessMemory_d9e7 {
  strings:
    $key_d9e7 = { 8e 95 [2] bc b7 [2] ba 82 [2] 94 82 [2] ab 9e }

  condition:
    any of them
}