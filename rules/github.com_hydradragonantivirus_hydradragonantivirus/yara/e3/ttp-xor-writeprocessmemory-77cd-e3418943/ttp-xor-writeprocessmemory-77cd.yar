rule TTP_XOR_WriteProcessMemory_77cd {
  strings:
    $key_77cd = { 20 bf [2] 12 9d [2] 14 a8 [2] 3a a8 [2] 05 b4 }

  condition:
    any of them
}