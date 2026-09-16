rule TTP_XOR_WriteProcessMemory_dfff {
  strings:
    $key_dfff = { 88 8d [2] ba af [2] bc 9a [2] 92 9a [2] ad 86 }

  condition:
    any of them
}