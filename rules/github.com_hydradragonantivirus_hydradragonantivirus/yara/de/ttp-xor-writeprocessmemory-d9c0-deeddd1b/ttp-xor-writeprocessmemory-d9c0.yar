rule TTP_XOR_WriteProcessMemory_d9c0 {
  strings:
    $key_d9c0 = { 8e b2 [2] bc 90 [2] ba a5 [2] 94 a5 [2] ab b9 }

  condition:
    any of them
}