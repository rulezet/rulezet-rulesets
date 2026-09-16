rule TTP_XOR_WriteProcessMemory_d9f6 {
  strings:
    $key_d9f6 = { 8e 84 [2] bc a6 [2] ba 93 [2] 94 93 [2] ab 8f }

  condition:
    any of them
}