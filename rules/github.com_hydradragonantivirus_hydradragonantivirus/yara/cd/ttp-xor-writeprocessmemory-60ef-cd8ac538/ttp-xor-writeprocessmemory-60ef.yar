rule TTP_XOR_WriteProcessMemory_60ef {
  strings:
    $key_60ef = { 37 9d [2] 05 bf [2] 03 8a [2] 2d 8a [2] 12 96 }

  condition:
    any of them
}