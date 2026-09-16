rule TTP_XOR_WriteProcessMemory_24ef {
  strings:
    $key_24ef = { 73 9d [2] 41 bf [2] 47 8a [2] 69 8a [2] 56 96 }

  condition:
    any of them
}