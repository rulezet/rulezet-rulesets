rule TTP_XOR_WriteProcessMemory_3df3 {
  strings:
    $key_3df3 = { 6a 81 [2] 58 a3 [2] 5e 96 [2] 70 96 [2] 4f 8a }

  condition:
    any of them
}