rule TTP_XOR_WriteProcessMemory_dfd1 {
  strings:
    $key_dfd1 = { 88 a3 [2] ba 81 [2] bc b4 [2] 92 b4 [2] ad a8 }

  condition:
    any of them
}