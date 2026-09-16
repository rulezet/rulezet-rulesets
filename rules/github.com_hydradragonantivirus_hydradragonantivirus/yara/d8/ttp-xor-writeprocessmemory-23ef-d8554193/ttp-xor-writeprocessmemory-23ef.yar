rule TTP_XOR_WriteProcessMemory_23ef {
  strings:
    $key_23ef = { 74 9d [2] 46 bf [2] 40 8a [2] 6e 8a [2] 51 96 }

  condition:
    any of them
}