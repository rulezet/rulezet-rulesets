rule TTP_XOR_WriteProcessMemory_6748 {
  strings:
    $key_6748 = { 30 3a [2] 02 18 [2] 04 2d [2] 2a 2d [2] 15 31 }

  condition:
    any of them
}