rule TTP_XOR_WriteProcessMemory_4ed1 {
  strings:
    $key_4ed1 = { 19 a3 [2] 2b 81 [2] 2d b4 [2] 03 b4 [2] 3c a8 }

  condition:
    any of them
}