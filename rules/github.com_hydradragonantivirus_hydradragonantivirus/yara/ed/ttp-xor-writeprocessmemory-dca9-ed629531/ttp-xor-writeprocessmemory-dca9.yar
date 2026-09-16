rule TTP_XOR_WriteProcessMemory_dca9 {
  strings:
    $key_dca9 = { 8b db [2] b9 f9 [2] bf cc [2] 91 cc [2] ae d0 }

  condition:
    any of them
}