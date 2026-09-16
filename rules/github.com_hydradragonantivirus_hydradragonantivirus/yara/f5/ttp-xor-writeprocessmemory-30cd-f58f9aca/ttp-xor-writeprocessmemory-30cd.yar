rule TTP_XOR_WriteProcessMemory_30cd {
  strings:
    $key_30cd = { 67 bf [2] 55 9d [2] 53 a8 [2] 7d a8 [2] 42 b4 }

  condition:
    any of them
}