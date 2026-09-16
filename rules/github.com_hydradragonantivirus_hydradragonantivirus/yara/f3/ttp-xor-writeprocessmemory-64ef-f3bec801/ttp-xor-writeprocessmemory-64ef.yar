rule TTP_XOR_WriteProcessMemory_64ef {
  strings:
    $key_64ef = { 33 9d [2] 01 bf [2] 07 8a [2] 29 8a [2] 16 96 }

  condition:
    any of them
}