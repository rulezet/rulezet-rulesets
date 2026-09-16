rule TTP_XOR_WriteProcessMemory_2d68 {
  strings:
    $key_2d68 = { 7a 1a [2] 48 38 [2] 4e 0d [2] 60 0d [2] 5f 11 }

  condition:
    any of them
}