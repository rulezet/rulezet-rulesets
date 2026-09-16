rule TTP_XOR_WriteProcessMemory_c879 {
  strings:
    $key_c879 = { 9f 0b [2] ad 29 [2] ab 1c [2] 85 1c [2] ba 00 }

  condition:
    any of them
}