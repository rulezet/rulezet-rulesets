rule TTP_XOR_WriteProcessMemory_d9dd {
  strings:
    $key_d9dd = { 8e af [2] bc 8d [2] ba b8 [2] 94 b8 [2] ab a4 }

  condition:
    any of them
}