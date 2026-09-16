rule TTP_XOR_WriteProcessMemory_6d72 {
  strings:
    $key_6d72 = { 3a 00 [2] 08 22 [2] 0e 17 [2] 20 17 [2] 1f 0b }

  condition:
    any of them
}