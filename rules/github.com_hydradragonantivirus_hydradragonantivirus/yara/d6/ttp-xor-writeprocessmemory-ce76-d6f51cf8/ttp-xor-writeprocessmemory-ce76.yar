rule TTP_XOR_WriteProcessMemory_ce76 {
  strings:
    $key_ce76 = { 99 04 [2] ab 26 [2] ad 13 [2] 83 13 [2] bc 0f }

  condition:
    any of them
}