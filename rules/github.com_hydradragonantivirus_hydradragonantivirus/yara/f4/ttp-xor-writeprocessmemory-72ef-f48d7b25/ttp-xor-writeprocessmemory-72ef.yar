rule TTP_XOR_WriteProcessMemory_72ef {
  strings:
    $key_72ef = { 25 9d [2] 17 bf [2] 11 8a [2] 3f 8a [2] 00 96 }

  condition:
    any of them
}