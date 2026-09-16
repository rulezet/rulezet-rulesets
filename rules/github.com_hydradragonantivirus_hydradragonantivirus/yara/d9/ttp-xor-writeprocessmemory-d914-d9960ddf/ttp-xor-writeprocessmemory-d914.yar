rule TTP_XOR_WriteProcessMemory_d914 {
  strings:
    $key_d914 = { 8e 66 [2] bc 44 [2] ba 71 [2] 94 71 [2] ab 6d }

  condition:
    any of them
}