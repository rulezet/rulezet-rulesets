rule TTP_XOR_WriteProcessMemory_7224 {
  strings:
    $key_7224 = { 25 56 [2] 17 74 [2] 11 41 [2] 3f 41 [2] 00 5d }

  condition:
    any of them
}