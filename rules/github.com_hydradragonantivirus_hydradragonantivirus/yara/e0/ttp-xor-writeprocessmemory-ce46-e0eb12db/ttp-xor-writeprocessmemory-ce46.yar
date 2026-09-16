rule TTP_XOR_WriteProcessMemory_ce46 {
  strings:
    $key_ce46 = { 99 34 [2] ab 16 [2] ad 23 [2] 83 23 [2] bc 3f }

  condition:
    any of them
}