rule TTP_XOR_WriteProcessMemory_1824 {
  strings:
    $key_1824 = { 4f 56 [2] 7d 74 [2] 7b 41 [2] 55 41 [2] 6a 5d }

  condition:
    any of them
}