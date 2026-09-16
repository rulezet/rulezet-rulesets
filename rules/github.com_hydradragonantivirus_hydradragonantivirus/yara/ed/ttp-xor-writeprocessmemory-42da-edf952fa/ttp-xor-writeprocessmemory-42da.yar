rule TTP_XOR_WriteProcessMemory_42da {
  strings:
    $key_42da = { 15 a8 [2] 27 8a [2] 21 bf [2] 0f bf [2] 30 a3 }

  condition:
    any of them
}