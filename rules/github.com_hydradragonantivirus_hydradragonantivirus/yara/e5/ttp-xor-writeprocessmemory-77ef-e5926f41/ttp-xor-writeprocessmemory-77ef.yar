rule TTP_XOR_WriteProcessMemory_77ef {
  strings:
    $key_77ef = { 20 9d [2] 12 bf [2] 14 8a [2] 3a 8a [2] 05 96 }

  condition:
    any of them
}