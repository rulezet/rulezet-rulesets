rule TTP_XOR_WriteProcessMemory_03ef {
  strings:
    $key_03ef = { 54 9d [2] 66 bf [2] 60 8a [2] 4e 8a [2] 71 96 }

  condition:
    any of them
}