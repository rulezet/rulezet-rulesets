rule TTP_XOR_WriteProcessMemory_dfdb {
  strings:
    $key_dfdb = { 88 a9 [2] ba 8b [2] bc be [2] 92 be [2] ad a2 }

  condition:
    any of them
}