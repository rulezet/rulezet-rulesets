rule TTP_XOR_WriteProcessMemory_c9f7 {
  strings:
    $key_c9f7 = { 9e 85 [2] ac a7 [2] aa 92 [2] 84 92 [2] bb 8e }

  condition:
    any of them
}