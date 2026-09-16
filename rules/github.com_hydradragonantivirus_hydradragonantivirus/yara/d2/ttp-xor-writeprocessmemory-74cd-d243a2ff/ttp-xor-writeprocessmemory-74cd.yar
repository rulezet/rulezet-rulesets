rule TTP_XOR_WriteProcessMemory_74cd {
  strings:
    $key_74cd = { 23 bf [2] 11 9d [2] 17 a8 [2] 39 a8 [2] 06 b4 }

  condition:
    any of them
}