rule TTP_XOR_WriteProcessMemory_34d4 {
  strings:
    $key_34d4 = { 63 a6 [2] 51 84 [2] 57 b1 [2] 79 b1 [2] 46 ad }

  condition:
    any of them
}