rule TTP_XOR_WriteProcessMemory_cede {
  strings:
    $key_cede = { 99 ac [2] ab 8e [2] ad bb [2] 83 bb [2] bc a7 }

  condition:
    any of them
}