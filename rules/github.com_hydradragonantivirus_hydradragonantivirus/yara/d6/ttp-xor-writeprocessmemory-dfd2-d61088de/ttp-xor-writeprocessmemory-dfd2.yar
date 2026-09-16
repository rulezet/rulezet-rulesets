rule TTP_XOR_WriteProcessMemory_dfd2 {
  strings:
    $key_dfd2 = { 88 a0 [2] ba 82 [2] bc b7 [2] 92 b7 [2] ad ab }

  condition:
    any of them
}