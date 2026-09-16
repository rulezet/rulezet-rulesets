rule TTP_XOR_WriteProcessMemory_1fcd {
  strings:
    $key_1fcd = { 48 bf [2] 7a 9d [2] 7c a8 [2] 52 a8 [2] 6d b4 }

  condition:
    any of them
}