rule TTP_XOR_WriteProcessMemory_07cd {
  strings:
    $key_07cd = { 50 bf [2] 62 9d [2] 64 a8 [2] 4a a8 [2] 75 b4 }

  condition:
    any of them
}