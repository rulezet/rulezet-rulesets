rule TTP_XOR_WriteProcessMemory_1724 {
  strings:
    $key_1724 = { 40 56 [2] 72 74 [2] 74 41 [2] 5a 41 [2] 65 5d }

  condition:
    any of them
}