rule TTP_XOR_WriteProcessMemory_3df2 {
  strings:
    $key_3df2 = { 6a 80 [2] 58 a2 [2] 5e 97 [2] 70 97 [2] 4f 8b }

  condition:
    any of them
}