rule TTP_XOR_WriteProcessMemory_ce58 {
  strings:
    $key_ce58 = { 99 2a [2] ab 08 [2] ad 3d [2] 83 3d [2] bc 21 }

  condition:
    any of them
}