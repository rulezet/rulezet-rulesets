rule TTP_XOR_WriteProcessMemory_d9cb {
  strings:
    $key_d9cb = { 8e b9 [2] bc 9b [2] ba ae [2] 94 ae [2] ab b2 }

  condition:
    any of them
}