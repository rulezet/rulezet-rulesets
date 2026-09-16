rule TTP_XOR_WriteProcessMemory_2d00 {
  strings:
    $key_2d00 = { 7a 72 [2] 48 50 [2] 4e 65 [2] 60 65 [2] 5f 79 }

  condition:
    any of them
}