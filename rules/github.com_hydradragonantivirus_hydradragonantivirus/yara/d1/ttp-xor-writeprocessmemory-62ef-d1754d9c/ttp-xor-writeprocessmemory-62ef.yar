rule TTP_XOR_WriteProcessMemory_62ef {
  strings:
    $key_62ef = { 35 9d [2] 07 bf [2] 01 8a [2] 2f 8a [2] 10 96 }

  condition:
    any of them
}