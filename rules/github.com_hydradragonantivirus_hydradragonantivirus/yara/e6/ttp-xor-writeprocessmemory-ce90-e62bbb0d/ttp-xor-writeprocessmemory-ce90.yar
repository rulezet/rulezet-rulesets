rule TTP_XOR_WriteProcessMemory_ce90 {
  strings:
    $key_ce90 = { 99 e2 [2] ab c0 [2] ad f5 [2] 83 f5 [2] bc e9 }

  condition:
    any of them
}