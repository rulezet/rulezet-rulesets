rule TTP_XOR_WriteProcessMemory_1174 {
  strings:
    $key_1174 = { 46 06 [2] 74 24 [2] 72 11 [2] 5c 11 [2] 63 0d }

  condition:
    any of them
}