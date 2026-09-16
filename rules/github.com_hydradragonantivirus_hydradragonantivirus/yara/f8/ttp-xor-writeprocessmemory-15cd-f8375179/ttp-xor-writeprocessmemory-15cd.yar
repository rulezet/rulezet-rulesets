rule TTP_XOR_WriteProcessMemory_15cd {
  strings:
    $key_15cd = { 42 bf [2] 70 9d [2] 76 a8 [2] 58 a8 [2] 67 b4 }

  condition:
    any of them
}