rule TTP_XOR_WriteProcessMemory_d9b5 {
  strings:
    $key_d9b5 = { 8e c7 [2] bc e5 [2] ba d0 [2] 94 d0 [2] ab cc }

  condition:
    any of them
}