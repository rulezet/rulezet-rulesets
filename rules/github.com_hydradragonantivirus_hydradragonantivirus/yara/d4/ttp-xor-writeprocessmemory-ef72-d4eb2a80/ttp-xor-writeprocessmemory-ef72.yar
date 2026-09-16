rule TTP_XOR_WriteProcessMemory_ef72 {
  strings:
    $key_ef72 = { b8 00 [2] 8a 22 [2] 8c 17 [2] a2 17 [2] 9d 0b }

  condition:
    any of them
}