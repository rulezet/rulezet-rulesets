rule TTP_XOR_WriteProcessMemory_67da {
  strings:
    $key_67da = { 30 a8 [2] 02 8a [2] 04 bf [2] 2a bf [2] 15 a3 }

  condition:
    any of them
}