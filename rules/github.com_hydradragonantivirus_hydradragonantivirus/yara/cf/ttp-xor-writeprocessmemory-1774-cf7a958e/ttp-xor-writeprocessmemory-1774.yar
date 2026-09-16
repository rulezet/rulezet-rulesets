rule TTP_XOR_WriteProcessMemory_1774 {
  strings:
    $key_1774 = { 40 06 [2] 72 24 [2] 74 11 [2] 5a 11 [2] 65 0d }

  condition:
    any of them
}