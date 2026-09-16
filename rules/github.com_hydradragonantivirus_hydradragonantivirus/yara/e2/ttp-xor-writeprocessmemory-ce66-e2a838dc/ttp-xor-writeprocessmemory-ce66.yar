rule TTP_XOR_WriteProcessMemory_ce66 {
  strings:
    $key_ce66 = { 99 14 [2] ab 36 [2] ad 03 [2] 83 03 [2] bc 1f }

  condition:
    any of them
}