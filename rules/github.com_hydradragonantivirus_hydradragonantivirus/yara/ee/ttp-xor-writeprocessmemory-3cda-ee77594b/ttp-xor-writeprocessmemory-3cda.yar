rule TTP_XOR_WriteProcessMemory_3cda {
  strings:
    $key_3cda = { 6b a8 [2] 59 8a [2] 5f bf [2] 71 bf [2] 4e a3 }

  condition:
    any of them
}