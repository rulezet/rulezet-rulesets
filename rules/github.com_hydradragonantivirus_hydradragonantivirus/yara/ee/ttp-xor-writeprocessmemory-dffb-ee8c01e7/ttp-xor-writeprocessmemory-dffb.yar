rule TTP_XOR_WriteProcessMemory_dffb {
  strings:
    $key_dffb = { 88 89 [2] ba ab [2] bc 9e [2] 92 9e [2] ad 82 }

  condition:
    any of them
}