rule TTP_XOR_WriteProcessMemory_54c4 {
  strings:
    $key_54c4 = { 03 b6 [2] 31 94 [2] 37 a1 [2] 19 a1 [2] 26 bd }

  condition:
    any of them
}