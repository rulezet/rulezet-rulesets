rule TTP_XOR_WriteProcessMemory_57cd {
  strings:
    $key_57cd = { 00 bf [2] 32 9d [2] 34 a8 [2] 1a a8 [2] 25 b4 }

  condition:
    any of them
}