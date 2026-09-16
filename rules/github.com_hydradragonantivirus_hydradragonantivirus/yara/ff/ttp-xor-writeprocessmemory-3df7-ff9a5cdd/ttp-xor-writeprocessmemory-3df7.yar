rule TTP_XOR_WriteProcessMemory_3df7 {
  strings:
    $key_3df7 = { 6a 85 [2] 58 a7 [2] 5e 92 [2] 70 92 [2] 4f 8e }

  condition:
    any of them
}