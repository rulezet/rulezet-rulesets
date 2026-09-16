rule TTP_XOR_WriteProcessMemory_11e4 {
  strings:
    $key_11e4 = { 46 96 [2] 74 b4 [2] 72 81 [2] 5c 81 [2] 63 9d }

  condition:
    any of them
}