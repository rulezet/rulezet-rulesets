rule TTP_XOR_WriteProcessMemory_06da {
  strings:
    $key_06da = { 51 a8 [2] 63 8a [2] 65 bf [2] 4b bf [2] 74 a3 }

  condition:
    any of them
}