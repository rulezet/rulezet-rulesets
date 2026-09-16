rule TTP_XOR_WriteProcessMemory_e4ef {
  strings:
    $key_e4ef = { b3 9d [2] 81 bf [2] 87 8a [2] a9 8a [2] 96 96 }

  condition:
    any of them
}