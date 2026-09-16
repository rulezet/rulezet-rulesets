rule TTP_XOR_WriteProcessMemory_f7ef {
  strings:
    $key_f7ef = { a0 9d [2] 92 bf [2] 94 8a [2] ba 8a [2] 85 96 }

  condition:
    any of them
}