rule TTP_XOR_WriteProcessMemory_6fcd {
  strings:
    $key_6fcd = { 38 bf [2] 0a 9d [2] 0c a8 [2] 22 a8 [2] 1d b4 }

  condition:
    any of them
}