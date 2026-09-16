rule TTP_XOR_WriteProcessMemory_11e7 {
  strings:
    $key_11e7 = { 46 95 [2] 74 b7 [2] 72 82 [2] 5c 82 [2] 63 9e }

  condition:
    any of them
}