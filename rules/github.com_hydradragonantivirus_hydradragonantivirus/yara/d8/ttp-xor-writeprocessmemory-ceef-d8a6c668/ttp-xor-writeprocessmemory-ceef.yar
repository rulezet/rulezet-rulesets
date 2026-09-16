rule TTP_XOR_WriteProcessMemory_ceef {
  strings:
    $key_ceef = { 99 9d [2] ab bf [2] ad 8a [2] 83 8a [2] bc 96 }

  condition:
    any of them
}