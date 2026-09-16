rule TTP_XOR_WriteProcessMemory_ce91 {
  strings:
    $key_ce91 = { 99 e3 [2] ab c1 [2] ad f4 [2] 83 f4 [2] bc e8 }

  condition:
    any of them
}