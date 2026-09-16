rule TTP_XOR_WriteProcessMemory_2d42 {
  strings:
    $key_2d42 = { 7a 30 [2] 48 12 [2] 4e 27 [2] 60 27 [2] 5f 3b }

  condition:
    any of them
}