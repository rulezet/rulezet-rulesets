rule TTP_XOR_WriteProcessMemory_5574 {
  strings:
    $key_5574 = { 02 06 [2] 30 24 [2] 36 11 [2] 18 11 [2] 27 0d }

  condition:
    any of them
}