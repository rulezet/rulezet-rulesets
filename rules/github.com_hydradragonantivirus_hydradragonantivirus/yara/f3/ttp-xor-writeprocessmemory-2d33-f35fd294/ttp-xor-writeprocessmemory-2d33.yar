rule TTP_XOR_WriteProcessMemory_2d33 {
  strings:
    $key_2d33 = { 7a 41 [2] 48 63 [2] 4e 56 [2] 60 56 [2] 5f 4a }

  condition:
    any of them
}