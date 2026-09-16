rule TTP_XOR_WriteProcessMemory_ce70 {
  strings:
    $key_ce70 = { 99 02 [2] ab 20 [2] ad 15 [2] 83 15 [2] bc 09 }

  condition:
    any of them
}