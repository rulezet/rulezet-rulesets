rule TTP_XOR_WriteProcessMemory_2d73 {
  strings:
    $key_2d73 = { 7a 01 [2] 48 23 [2] 4e 16 [2] 60 16 [2] 5f 0a }

  condition:
    any of them
}