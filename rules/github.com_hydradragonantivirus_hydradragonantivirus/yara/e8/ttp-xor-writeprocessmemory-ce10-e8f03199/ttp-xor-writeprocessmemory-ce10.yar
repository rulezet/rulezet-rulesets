rule TTP_XOR_WriteProcessMemory_ce10 {
  strings:
    $key_ce10 = { 99 62 [2] ab 40 [2] ad 75 [2] 83 75 [2] bc 69 }

  condition:
    any of them
}