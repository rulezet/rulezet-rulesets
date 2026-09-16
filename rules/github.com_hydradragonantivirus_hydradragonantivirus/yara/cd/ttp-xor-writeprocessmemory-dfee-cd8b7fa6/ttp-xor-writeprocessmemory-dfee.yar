rule TTP_XOR_WriteProcessMemory_dfee {
  strings:
    $key_dfee = { 88 9c [2] ba be [2] bc 8b [2] 92 8b [2] ad 97 }

  condition:
    any of them
}