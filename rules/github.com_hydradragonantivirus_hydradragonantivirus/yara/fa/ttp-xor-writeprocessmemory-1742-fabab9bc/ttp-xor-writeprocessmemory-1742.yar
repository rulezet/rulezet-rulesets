rule TTP_XOR_WriteProcessMemory_1742 {
  strings:
    $key_1742 = { 40 30 [2] 72 12 [2] 74 27 [2] 5a 27 [2] 65 3b }

  condition:
    any of them
}