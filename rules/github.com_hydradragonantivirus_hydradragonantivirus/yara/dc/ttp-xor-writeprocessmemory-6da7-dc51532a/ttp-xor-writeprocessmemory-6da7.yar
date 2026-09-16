rule TTP_XOR_WriteProcessMemory_6da7 {
  strings:
    $key_6da7 = { 3a d5 [2] 08 f7 [2] 0e c2 [2] 20 c2 [2] 1f de }

  condition:
    any of them
}