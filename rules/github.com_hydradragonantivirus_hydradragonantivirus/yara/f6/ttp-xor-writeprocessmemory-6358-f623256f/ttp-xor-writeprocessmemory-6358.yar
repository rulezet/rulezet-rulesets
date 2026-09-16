rule TTP_XOR_WriteProcessMemory_6358 {
  strings:
    $key_6358 = { 34 2a [2] 06 08 [2] 00 3d [2] 2e 3d [2] 11 21 }

  condition:
    any of them
}