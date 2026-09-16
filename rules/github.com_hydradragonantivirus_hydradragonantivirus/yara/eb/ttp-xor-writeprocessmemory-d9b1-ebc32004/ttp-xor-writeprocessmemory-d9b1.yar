rule TTP_XOR_WriteProcessMemory_d9b1 {
  strings:
    $key_d9b1 = { 8e c3 [2] bc e1 [2] ba d4 [2] 94 d4 [2] ab c8 }

  condition:
    any of them
}