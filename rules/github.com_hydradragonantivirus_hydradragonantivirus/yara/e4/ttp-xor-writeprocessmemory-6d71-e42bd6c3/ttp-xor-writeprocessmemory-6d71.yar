rule TTP_XOR_WriteProcessMemory_6d71 {
  strings:
    $key_6d71 = { 3a 03 [2] 08 21 [2] 0e 14 [2] 20 14 [2] 1f 08 }

  condition:
    any of them
}