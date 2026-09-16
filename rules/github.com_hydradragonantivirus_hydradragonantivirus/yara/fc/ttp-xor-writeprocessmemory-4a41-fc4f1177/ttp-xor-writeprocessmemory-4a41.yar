rule TTP_XOR_WriteProcessMemory_4a41 {
  strings:
    $key_4a41 = { 1d 33 [2] 2f 11 [2] 29 24 [2] 07 24 [2] 38 38 }

  condition:
    any of them
}