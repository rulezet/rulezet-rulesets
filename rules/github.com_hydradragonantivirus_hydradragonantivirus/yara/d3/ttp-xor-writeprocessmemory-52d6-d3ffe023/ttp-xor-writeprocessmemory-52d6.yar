rule TTP_XOR_WriteProcessMemory_52d6 {
  strings:
    $key_52d6 = { 05 a4 [2] 37 86 [2] 31 b3 [2] 1f b3 [2] 20 af }

  condition:
    any of them
}