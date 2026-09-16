rule TTP_XOR_WriteProcessMemory_dfde {
  strings:
    $key_dfde = { 88 ac [2] ba 8e [2] bc bb [2] 92 bb [2] ad a7 }

  condition:
    any of them
}