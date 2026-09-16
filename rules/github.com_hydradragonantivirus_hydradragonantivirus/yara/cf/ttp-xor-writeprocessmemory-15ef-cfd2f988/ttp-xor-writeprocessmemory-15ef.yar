rule TTP_XOR_WriteProcessMemory_15ef {
  strings:
    $key_15ef = { 42 9d [2] 70 bf [2] 76 8a [2] 58 8a [2] 67 96 }

  condition:
    any of them
}