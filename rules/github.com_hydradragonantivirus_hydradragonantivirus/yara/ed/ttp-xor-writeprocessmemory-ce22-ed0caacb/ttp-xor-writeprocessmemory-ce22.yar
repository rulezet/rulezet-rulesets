rule TTP_XOR_WriteProcessMemory_ce22 {
  strings:
    $key_ce22 = { 99 50 [2] ab 72 [2] ad 47 [2] 83 47 [2] bc 5b }

  condition:
    any of them
}