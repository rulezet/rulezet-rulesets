rule TTP_XOR_WriteProcessMemory_33cd {
  strings:
    $key_33cd = { 64 bf [2] 56 9d [2] 50 a8 [2] 7e a8 [2] 41 b4 }

  condition:
    any of them
}