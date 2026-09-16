rule TTP_XOR_WriteProcessMemory_5cda {
  strings:
    $key_5cda = { 0b a8 [2] 39 8a [2] 3f bf [2] 11 bf [2] 2e a3 }

  condition:
    any of them
}