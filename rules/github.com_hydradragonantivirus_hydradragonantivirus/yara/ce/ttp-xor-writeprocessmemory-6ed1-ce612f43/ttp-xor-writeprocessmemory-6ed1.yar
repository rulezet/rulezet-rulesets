rule TTP_XOR_WriteProcessMemory_6ed1 {
  strings:
    $key_6ed1 = { 39 a3 [2] 0b 81 [2] 0d b4 [2] 23 b4 [2] 1c a8 }

  condition:
    any of them
}