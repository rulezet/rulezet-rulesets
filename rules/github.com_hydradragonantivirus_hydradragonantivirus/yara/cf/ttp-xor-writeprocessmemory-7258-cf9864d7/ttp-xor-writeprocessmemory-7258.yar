rule TTP_XOR_WriteProcessMemory_7258 {
  strings:
    $key_7258 = { 25 2a [2] 17 08 [2] 11 3d [2] 3f 3d [2] 00 21 }

  condition:
    any of them
}