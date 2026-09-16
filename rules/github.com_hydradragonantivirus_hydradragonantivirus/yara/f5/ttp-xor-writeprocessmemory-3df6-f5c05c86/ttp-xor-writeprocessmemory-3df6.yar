rule TTP_XOR_WriteProcessMemory_3df6 {
  strings:
    $key_3df6 = { 6a 84 [2] 58 a6 [2] 5e 93 [2] 70 93 [2] 4f 8f }

  condition:
    any of them
}