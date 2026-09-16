rule TTP_XOR_WriteProcessMemory_59f7 {
  strings:
    $key_59f7 = { 0e 85 [2] 3c a7 [2] 3a 92 [2] 14 92 [2] 2b 8e }

  condition:
    any of them
}