rule TTP_XOR_WriteProcessMemory_2a41 {
  strings:
    $key_2a41 = { 7d 33 [2] 4f 11 [2] 49 24 [2] 67 24 [2] 58 38 }

  condition:
    any of them
}