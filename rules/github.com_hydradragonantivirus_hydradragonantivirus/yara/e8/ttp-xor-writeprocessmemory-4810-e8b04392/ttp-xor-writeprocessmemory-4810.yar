rule TTP_XOR_WriteProcessMemory_4810 {
  strings:
    $key_4810 = { 1f 62 [2] 2d 40 [2] 2b 75 [2] 05 75 [2] 3a 69 }

  condition:
    any of them
}