rule TTP_XOR_WriteProcessMemory_7632 {
  strings:
    $key_7632 = { 21 40 [2] 13 62 [2] 15 57 [2] 3b 57 [2] 04 4b }

  condition:
    any of them
}