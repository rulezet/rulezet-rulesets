rule TTP_XOR_WriteProcessMemory_7637 {
  strings:
    $key_7637 = { 21 45 [2] 13 67 [2] 15 52 [2] 3b 52 [2] 04 4e }

  condition:
    any of them
}