rule TTP_XOR_WriteProcessMemory_ced3 {
  strings:
    $key_ced3 = { 99 a1 [2] ab 83 [2] ad b6 [2] 83 b6 [2] bc aa }

  condition:
    any of them
}