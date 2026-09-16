rule TTP_XOR_WriteProcessMemory_2d60 {
  strings:
    $key_2d60 = { 7a 12 [2] 48 30 [2] 4e 05 [2] 60 05 [2] 5f 19 }

  condition:
    any of them
}