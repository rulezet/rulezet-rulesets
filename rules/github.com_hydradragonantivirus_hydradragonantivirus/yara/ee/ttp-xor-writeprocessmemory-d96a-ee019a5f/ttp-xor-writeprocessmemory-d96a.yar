rule TTP_XOR_WriteProcessMemory_d96a {
  strings:
    $key_d96a = { 8e 18 [2] bc 3a [2] ba 0f [2] 94 0f [2] ab 13 }

  condition:
    any of them
}