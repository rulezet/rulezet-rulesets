rule TTP_XOR_WriteProcessMemory_f1fe {
  strings:
    $key_f1fe = { a6 8c [2] 94 ae [2] 92 9b [2] bc 9b [2] 83 87 }

  condition:
    any of them
}