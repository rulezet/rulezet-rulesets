rule TTP_XOR_WriteProcessMemory_d9b3 {
  strings:
    $key_d9b3 = { 8e c1 [2] bc e3 [2] ba d6 [2] 94 d6 [2] ab ca }

  condition:
    any of them
}