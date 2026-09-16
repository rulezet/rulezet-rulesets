rule TTP_XOR_WriteProcessMemory_1132 {
  strings:
    $key_1132 = { 46 40 [2] 74 62 [2] 72 57 [2] 5c 57 [2] 63 4b }

  condition:
    any of them
}