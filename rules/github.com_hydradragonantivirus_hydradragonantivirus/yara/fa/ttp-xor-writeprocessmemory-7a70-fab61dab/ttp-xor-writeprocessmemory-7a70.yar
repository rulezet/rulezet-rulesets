rule TTP_XOR_WriteProcessMemory_7a70 {
  strings:
    $key_7a70 = { 2d 02 [2] 1f 20 [2] 19 15 [2] 37 15 [2] 08 09 }

  condition:
    any of them
}