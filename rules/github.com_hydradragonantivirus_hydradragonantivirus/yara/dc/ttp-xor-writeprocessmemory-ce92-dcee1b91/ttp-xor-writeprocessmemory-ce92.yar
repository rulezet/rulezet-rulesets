rule TTP_XOR_WriteProcessMemory_ce92 {
  strings:
    $key_ce92 = { 99 e0 [2] ab c2 [2] ad f7 [2] 83 f7 [2] bc eb }

  condition:
    any of them
}