rule TTP_XOR_WriteProcessMemory_41da {
  strings:
    $key_41da = { 16 a8 [2] 24 8a [2] 22 bf [2] 0c bf [2] 33 a3 }

  condition:
    any of them
}