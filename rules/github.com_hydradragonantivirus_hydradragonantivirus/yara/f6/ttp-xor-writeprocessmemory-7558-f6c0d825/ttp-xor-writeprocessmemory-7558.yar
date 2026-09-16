rule TTP_XOR_WriteProcessMemory_7558 {
  strings:
    $key_7558 = { 22 2a [2] 10 08 [2] 16 3d [2] 38 3d [2] 07 21 }

  condition:
    any of them
}