rule TTP_XOR_WriteProcessMemory_d992 {
  strings:
    $key_d992 = { 8e e0 [2] bc c2 [2] ba f7 [2] 94 f7 [2] ab eb }

  condition:
    any of them
}