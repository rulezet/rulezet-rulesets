rule TTP_XOR_WriteProcessMemory_62cd {
  strings:
    $key_62cd = { 35 bf [2] 07 9d [2] 01 a8 [2] 2f a8 [2] 10 b4 }

  condition:
    any of them
}