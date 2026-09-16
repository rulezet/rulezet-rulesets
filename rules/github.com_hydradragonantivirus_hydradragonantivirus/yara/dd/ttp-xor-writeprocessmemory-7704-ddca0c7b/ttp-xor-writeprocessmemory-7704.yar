rule TTP_XOR_WriteProcessMemory_7704 {
  strings:
    $key_7704 = { 20 76 [2] 12 54 [2] 14 61 [2] 3a 61 [2] 05 7d }

  condition:
    any of them
}