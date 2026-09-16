rule TTP_XOR_WriteProcessMemory_d92a {
  strings:
    $key_d92a = { 8e 58 [2] bc 7a [2] ba 4f [2] 94 4f [2] ab 53 }

  condition:
    any of them
}