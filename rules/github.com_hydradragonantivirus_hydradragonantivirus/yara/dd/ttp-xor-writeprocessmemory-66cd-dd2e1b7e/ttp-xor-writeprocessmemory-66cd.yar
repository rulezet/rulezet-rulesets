rule TTP_XOR_WriteProcessMemory_66cd {
  strings:
    $key_66cd = { 31 bf [2] 03 9d [2] 05 a8 [2] 2b a8 [2] 14 b4 }

  condition:
    any of them
}