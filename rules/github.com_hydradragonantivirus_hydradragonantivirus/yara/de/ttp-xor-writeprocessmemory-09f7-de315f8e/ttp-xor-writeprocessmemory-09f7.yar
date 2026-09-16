rule TTP_XOR_WriteProcessMemory_09f7 {
  strings:
    $key_09f7 = { 5e 85 [2] 6c a7 [2] 6a 92 [2] 44 92 [2] 7b 8e }

  condition:
    any of them
}