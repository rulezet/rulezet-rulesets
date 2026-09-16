rule TTP_XOR_WriteProcessMemory_7324 {
  strings:
    $key_7324 = { 24 56 [2] 16 74 [2] 10 41 [2] 3e 41 [2] 01 5d }

  condition:
    any of them
}