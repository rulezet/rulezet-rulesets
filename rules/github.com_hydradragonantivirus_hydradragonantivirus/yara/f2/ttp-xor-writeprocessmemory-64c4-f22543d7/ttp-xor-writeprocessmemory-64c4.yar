rule TTP_XOR_WriteProcessMemory_64c4 {
  strings:
    $key_64c4 = { 33 b6 [2] 01 94 [2] 07 a1 [2] 29 a1 [2] 16 bd }

  condition:
    any of them
}