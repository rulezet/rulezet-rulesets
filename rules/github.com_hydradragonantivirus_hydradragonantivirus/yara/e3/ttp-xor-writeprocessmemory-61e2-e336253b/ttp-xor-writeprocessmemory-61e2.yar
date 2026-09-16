rule TTP_XOR_WriteProcessMemory_61e2 {
  strings:
    $key_61e2 = { 36 90 [2] 04 b2 [2] 02 87 [2] 2c 87 [2] 13 9b }

  condition:
    any of them
}