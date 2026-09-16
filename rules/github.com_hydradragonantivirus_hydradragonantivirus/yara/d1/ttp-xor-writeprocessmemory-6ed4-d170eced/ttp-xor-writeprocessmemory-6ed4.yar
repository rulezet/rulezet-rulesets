rule TTP_XOR_WriteProcessMemory_6ed4 {
  strings:
    $key_6ed4 = { 39 a6 [2] 0b 84 [2] 0d b1 [2] 23 b1 [2] 1c ad }

  condition:
    any of them
}