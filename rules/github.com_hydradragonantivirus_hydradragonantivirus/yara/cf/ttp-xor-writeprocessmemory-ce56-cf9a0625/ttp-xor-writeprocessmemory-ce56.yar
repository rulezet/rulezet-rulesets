rule TTP_XOR_WriteProcessMemory_ce56 {
  strings:
    $key_ce56 = { 99 24 [2] ab 06 [2] ad 33 [2] 83 33 [2] bc 2f }

  condition:
    any of them
}