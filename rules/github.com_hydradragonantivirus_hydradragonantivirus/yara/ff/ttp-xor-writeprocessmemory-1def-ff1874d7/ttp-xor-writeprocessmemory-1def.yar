rule TTP_XOR_WriteProcessMemory_1def {
  strings:
    $key_1def = { 4a 9d [2] 78 bf [2] 7e 8a [2] 50 8a [2] 6f 96 }

  condition:
    any of them
}