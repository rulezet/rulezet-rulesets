rule TTP_XOR_WriteProcessMemory_1124 {
  strings:
    $key_1124 = { 46 56 [2] 74 74 [2] 72 41 [2] 5c 41 [2] 63 5d }

  condition:
    any of them
}