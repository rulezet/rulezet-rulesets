rule TTP_XOR_WriteProcessMemory_63da {
  strings:
    $key_63da = { 34 a8 [2] 06 8a [2] 00 bf [2] 2e bf [2] 11 a3 }

  condition:
    any of them
}