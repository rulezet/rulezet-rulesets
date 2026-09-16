rule TTP_XOR_WriteProcessMemory_46da {
  strings:
    $key_46da = { 11 a8 [2] 23 8a [2] 25 bf [2] 0b bf [2] 34 a3 }

  condition:
    any of them
}