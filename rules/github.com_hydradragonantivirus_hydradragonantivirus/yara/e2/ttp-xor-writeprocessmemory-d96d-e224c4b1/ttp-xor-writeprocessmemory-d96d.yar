rule TTP_XOR_WriteProcessMemory_d96d {
  strings:
    $key_d96d = { 8e 1f [2] bc 3d [2] ba 08 [2] 94 08 [2] ab 14 }

  condition:
    any of them
}