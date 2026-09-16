rule TTP_XOR_WriteProcessMemory_00da {
  strings:
    $key_00da = { 57 a8 [2] 65 8a [2] 63 bf [2] 4d bf [2] 72 a3 }

  condition:
    any of them
}