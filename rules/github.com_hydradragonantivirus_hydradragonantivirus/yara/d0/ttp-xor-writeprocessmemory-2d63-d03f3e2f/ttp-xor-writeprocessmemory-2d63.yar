rule TTP_XOR_WriteProcessMemory_2d63 {
  strings:
    $key_2d63 = { 7a 11 [2] 48 33 [2] 4e 06 [2] 60 06 [2] 5f 1a }

  condition:
    any of them
}