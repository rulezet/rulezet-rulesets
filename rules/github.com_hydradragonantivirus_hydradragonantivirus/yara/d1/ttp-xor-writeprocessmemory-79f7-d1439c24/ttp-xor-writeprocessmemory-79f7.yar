rule TTP_XOR_WriteProcessMemory_79f7 {
  strings:
    $key_79f7 = { 2e 85 [2] 1c a7 [2] 1a 92 [2] 34 92 [2] 0b 8e }

  condition:
    any of them
}