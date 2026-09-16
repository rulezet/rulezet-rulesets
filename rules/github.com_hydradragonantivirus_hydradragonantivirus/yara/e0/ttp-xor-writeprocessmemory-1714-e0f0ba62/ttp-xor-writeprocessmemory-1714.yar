rule TTP_XOR_WriteProcessMemory_1714 {
  strings:
    $key_1714 = { 40 66 [2] 72 44 [2] 74 71 [2] 5a 71 [2] 65 6d }

  condition:
    any of them
}