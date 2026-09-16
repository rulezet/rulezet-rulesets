rule TTP_XOR_WriteProcessMemory_1113 {
  strings:
    $key_1113 = { 46 61 [2] 74 43 [2] 72 76 [2] 5c 76 [2] 63 6a }

  condition:
    any of them
}