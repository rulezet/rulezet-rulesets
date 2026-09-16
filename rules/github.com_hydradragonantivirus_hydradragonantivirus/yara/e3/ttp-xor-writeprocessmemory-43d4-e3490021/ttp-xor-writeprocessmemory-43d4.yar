rule TTP_XOR_WriteProcessMemory_43d4 {
  strings:
    $key_43d4 = { 14 a6 [2] 26 84 [2] 20 b1 [2] 0e b1 [2] 31 ad }

  condition:
    any of them
}