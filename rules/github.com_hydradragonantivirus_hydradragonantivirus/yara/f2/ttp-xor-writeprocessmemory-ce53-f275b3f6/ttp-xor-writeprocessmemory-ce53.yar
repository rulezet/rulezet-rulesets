rule TTP_XOR_WriteProcessMemory_ce53 {
  strings:
    $key_ce53 = { 99 21 [2] ab 03 [2] ad 36 [2] 83 36 [2] bc 2a }

  condition:
    any of them
}