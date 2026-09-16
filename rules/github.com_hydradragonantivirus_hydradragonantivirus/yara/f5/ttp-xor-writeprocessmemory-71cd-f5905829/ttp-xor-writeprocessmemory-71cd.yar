rule TTP_XOR_WriteProcessMemory_71cd {
  strings:
    $key_71cd = { 26 bf [2] 14 9d [2] 12 a8 [2] 3c a8 [2] 03 b4 }

  condition:
    any of them
}