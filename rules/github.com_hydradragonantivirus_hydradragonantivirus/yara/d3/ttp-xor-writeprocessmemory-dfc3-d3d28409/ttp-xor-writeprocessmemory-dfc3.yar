rule TTP_XOR_WriteProcessMemory_dfc3 {
  strings:
    $key_dfc3 = { 88 b1 [2] ba 93 [2] bc a6 [2] 92 a6 [2] ad ba }

  condition:
    any of them
}