rule TTP_XOR_WriteProcessMemory_6ed6 {
  strings:
    $key_6ed6 = { 39 a4 [2] 0b 86 [2] 0d b3 [2] 23 b3 [2] 1c af }

  condition:
    any of them
}