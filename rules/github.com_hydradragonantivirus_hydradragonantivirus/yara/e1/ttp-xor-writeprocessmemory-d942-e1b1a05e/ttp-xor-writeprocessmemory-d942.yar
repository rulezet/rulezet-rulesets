rule TTP_XOR_WriteProcessMemory_d942 {
  strings:
    $key_d942 = { 8e 30 [2] bc 12 [2] ba 27 [2] 94 27 [2] ab 3b }

  condition:
    any of them
}