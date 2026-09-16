rule TTP_XOR_WriteProcessMemory_79c8 {
  strings:
    $key_79c8 = { 2e ba [2] 1c 98 [2] 1a ad [2] 34 ad [2] 0b b1 }

  condition:
    any of them
}