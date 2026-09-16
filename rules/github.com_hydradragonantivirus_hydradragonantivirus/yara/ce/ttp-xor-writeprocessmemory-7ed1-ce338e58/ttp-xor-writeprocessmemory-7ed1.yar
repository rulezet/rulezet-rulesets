rule TTP_XOR_WriteProcessMemory_7ed1 {
  strings:
    $key_7ed1 = { 29 a3 [2] 1b 81 [2] 1d b4 [2] 33 b4 [2] 0c a8 }

  condition:
    any of them
}