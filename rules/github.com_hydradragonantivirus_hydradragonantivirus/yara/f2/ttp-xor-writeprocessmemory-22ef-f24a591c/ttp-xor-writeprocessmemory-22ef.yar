rule TTP_XOR_WriteProcessMemory_22ef {
  strings:
    $key_22ef = { 75 9d [2] 47 bf [2] 41 8a [2] 6f 8a [2] 50 96 }

  condition:
    any of them
}