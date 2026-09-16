rule TTP_XOR_WriteProcessMemory_50cd {
  strings:
    $key_50cd = { 07 bf [2] 35 9d [2] 33 a8 [2] 1d a8 [2] 22 b4 }

  condition:
    any of them
}