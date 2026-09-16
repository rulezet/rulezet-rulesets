rule TTP_XOR_WriteProcessMemory_56ef {
  strings:
    $key_56ef = { 01 9d [2] 33 bf [2] 35 8a [2] 1b 8a [2] 24 96 }

  condition:
    any of them
}