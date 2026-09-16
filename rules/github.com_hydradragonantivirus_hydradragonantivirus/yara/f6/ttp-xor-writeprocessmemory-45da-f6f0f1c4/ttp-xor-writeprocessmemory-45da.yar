rule TTP_XOR_WriteProcessMemory_45da {
  strings:
    $key_45da = { 12 a8 [2] 20 8a [2] 26 bf [2] 08 bf [2] 37 a3 }

  condition:
    any of them
}