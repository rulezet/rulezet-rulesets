rule TTP_XOR_WriteProcessMemory_d7cd {
  strings:
    $key_d7cd = { 80 bf [2] b2 9d [2] b4 a8 [2] 9a a8 [2] a5 b4 }

  condition:
    any of them
}