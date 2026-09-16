rule TTP_XOR_WriteProcessMemory_1ed6 {
  strings:
    $key_1ed6 = { 49 a4 [2] 7b 86 [2] 7d b3 [2] 53 b3 [2] 6c af }

  condition:
    any of them
}