rule TTP_XOR_WriteProcessMemory_ce6d {
  strings:
    $key_ce6d = { 99 1f [2] ab 3d [2] ad 08 [2] 83 08 [2] bc 14 }

  condition:
    any of them
}