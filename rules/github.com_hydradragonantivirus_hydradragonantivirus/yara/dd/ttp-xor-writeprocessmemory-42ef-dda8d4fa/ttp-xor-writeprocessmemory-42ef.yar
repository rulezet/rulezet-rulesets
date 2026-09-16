rule TTP_XOR_WriteProcessMemory_42ef {
  strings:
    $key_42ef = { 15 9d [2] 27 bf [2] 21 8a [2] 0f 8a [2] 30 96 }

  condition:
    any of them
}