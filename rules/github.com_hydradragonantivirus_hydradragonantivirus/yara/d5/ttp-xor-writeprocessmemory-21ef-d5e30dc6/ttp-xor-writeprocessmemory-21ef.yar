rule TTP_XOR_WriteProcessMemory_21ef {
  strings:
    $key_21ef = { 76 9d [2] 44 bf [2] 42 8a [2] 6c 8a [2] 53 96 }

  condition:
    any of them
}