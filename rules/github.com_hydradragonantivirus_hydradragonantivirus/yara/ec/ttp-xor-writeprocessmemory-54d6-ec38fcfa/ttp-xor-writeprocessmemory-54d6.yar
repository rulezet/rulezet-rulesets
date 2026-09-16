rule TTP_XOR_WriteProcessMemory_54d6 {
  strings:
    $key_54d6 = { 03 a4 [2] 31 86 [2] 37 b3 [2] 19 b3 [2] 26 af }

  condition:
    any of them
}