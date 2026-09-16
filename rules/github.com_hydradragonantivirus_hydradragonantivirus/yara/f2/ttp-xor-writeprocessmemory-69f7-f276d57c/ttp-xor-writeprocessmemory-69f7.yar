rule TTP_XOR_WriteProcessMemory_69f7 {
  strings:
    $key_69f7 = { 3e 85 [2] 0c a7 [2] 0a 92 [2] 24 92 [2] 1b 8e }

  condition:
    any of them
}