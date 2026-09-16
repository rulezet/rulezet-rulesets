rule TTP_XOR_WriteProcessMemory_4e10 {
  strings:
    $key_4e10 = { 19 62 [2] 2b 40 [2] 2d 75 [2] 03 75 [2] 3c 69 }

  condition:
    any of them
}