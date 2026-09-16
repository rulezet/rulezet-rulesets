rule TTP_XOR_WriteProcessMemory_ce42 {
  strings:
    $key_ce42 = { 99 30 [2] ab 12 [2] ad 27 [2] 83 27 [2] bc 3b }

  condition:
    any of them
}