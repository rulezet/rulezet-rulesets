rule TTP_XOR_WriteProcessMemory_0eda {
  strings:
    $key_0eda = { 59 a8 [2] 6b 8a [2] 6d bf [2] 43 bf [2] 7c a3 }

  condition:
    any of them
}