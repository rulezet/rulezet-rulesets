rule TTP_XOR_WriteProcessMemory_d6da {
  strings:
    $key_d6da = { 81 a8 [2] b3 8a [2] b5 bf [2] 9b bf [2] a4 a3 }

  condition:
    any of them
}