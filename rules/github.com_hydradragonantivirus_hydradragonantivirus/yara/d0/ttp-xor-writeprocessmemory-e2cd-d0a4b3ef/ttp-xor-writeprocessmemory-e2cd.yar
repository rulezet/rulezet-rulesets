rule TTP_XOR_WriteProcessMemory_e2cd {
  strings:
    $key_e2cd = { b5 bf [2] 87 9d [2] 81 a8 [2] af a8 [2] 90 b4 }

  condition:
    any of them
}