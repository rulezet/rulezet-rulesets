rule TTP_XOR_WriteProcessMemory_72cd {
  strings:
    $key_72cd = { 25 bf [2] 17 9d [2] 11 a8 [2] 3f a8 [2] 00 b4 }

  condition:
    any of them
}