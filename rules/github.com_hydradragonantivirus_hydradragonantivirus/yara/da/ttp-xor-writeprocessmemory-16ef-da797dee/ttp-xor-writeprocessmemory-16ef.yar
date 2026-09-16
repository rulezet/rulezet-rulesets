rule TTP_XOR_WriteProcessMemory_16ef {
  strings:
    $key_16ef = { 41 9d [2] 73 bf [2] 75 8a [2] 5b 8a [2] 64 96 }

  condition:
    any of them
}