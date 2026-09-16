rule TTP_XOR_WriteProcessMemory_d9d1 {
  strings:
    $key_d9d1 = { 8e a3 [2] bc 81 [2] ba b4 [2] 94 b4 [2] ab a8 }

  condition:
    any of them
}