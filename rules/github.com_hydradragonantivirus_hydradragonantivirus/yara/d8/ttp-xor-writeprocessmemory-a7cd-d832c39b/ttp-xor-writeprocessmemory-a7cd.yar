rule TTP_XOR_WriteProcessMemory_a7cd {
  strings:
    $key_a7cd = { f0 bf [2] c2 9d [2] c4 a8 [2] ea a8 [2] d5 b4 }

  condition:
    any of them
}